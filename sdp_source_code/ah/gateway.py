#!/usr/bin/env python3
import socket
import struct
import json
import threading
import sys
import time
import os
import subprocess
import datetime
import signal
from tls_util import make_client_ctx, make_server_ctx
import cert_manager

# ==========================================
# [통합 설정] Gateway Configuration
# ==========================================
# 1) Controller 정보 (컨트롤 플레인 IP로 설정)
#    - 컨트롤 플레인(예: 172.16.x.x)에서만 Controller에 붙도록 구성하는 것이 정석
CONTROLLER_IP = '172.16.255.2'
CONTROLLER_IH_PORT = 4433  # IH로서 접속할 포트
CONTROLLER_AH_PORT = 4444  # AH로서 접속할 포트

# 2) (권장) AH가 Controller에 등록할 "데이터 플레인" IP
#    - Controller가 IH에게 내려주는 AH address는 이 값(data_ip)이어야 데이터 플레인 분리됨
#    - 예: wazuh-manager라면 192.168.100.250
AH_DATA_IP = '192.168.100.250'   # ★ 너 환경에 맞게 고정 추천
# AH_DATA_IP = None              # 필요 시 None으로 두고 fallback 사용 가능(권장 X)

# 3) (권장) AH 리스너 바인딩 분리
#    - auth 포트는 컨트롤 플레인 NIC(172.16...)에서만 리슨
#    - data 포트는 데이터 플레인 NIC(192.168.100...)에서만 리슨
#    - 분리 안 하면 0.0.0.0로 유지
AUTH_BIND_IP = '0.0.0.0'         # 예: 172.16.x.x로 고정 권장
DATA_BIND_IP = '0.0.0.0'         # 예: 192.168.100.250로 고정 권장

# 4) [AH 역할] 이 Gateway가 보호할 로컬 서비스 기본값(대부분 service_map으로 override 됨)
#    - service_id 기반 라우팅이 정상 동작하면 아래 PROTECTED_*는 fallback 정도로만 쓰임
PROTECTED_TARGET_IP = '127.0.0.1'
PROTECTED_TARGET_PORT = 9200  # fallback

# 5) [IH 역할] 로컬 사용자가 접속할 진입점(OUTPUT REDIRECT로 들어오는 포트)
LOCAL_PROXY_IP = '127.0.0.1'
LOCAL_PROXY_PORT = 5020

# 6) fwknop 설정 파일
FWKNOP_ACCESS_CONF = "/etc/fwknop/access.conf"

# [공유 자원] 파일 쓰기 충돌 방지용 Lock
file_lock = threading.Lock()


# ==========================================
# [공통 유틸리티]
# ==========================================
def recv_until_newline(sock):
    """줄바꿈 문자(\n)가 나올 때까지 읽는 함수"""
    data = b''
    while True:
        try:
            chunk = sock.recv(1)
            if not chunk:
                return None
            data += chunk
            if chunk == b'\n':
                break
        except:
            return None
    return data


def recvall(sock, n):
    """
    [중요] TCP 패킷 분할(Fragmentation) 방지 함수
    정확히 n바이트를 모두 수신할 때까지 반복해서 읽습니다.
    """
    data = b''
    while len(data) < n:
        try:
            packet = sock.recv(n - len(data))
            if not packet:
                return None
            data += packet
        except:
            return None
    return data


def get_src_ip(dest_ip: str) -> str:
    """
    dest_ip로 나갈 때 커널이 선택하는 소스 IP를 얻는다.
    (멀티홈 환경에서 mgmt/data NIC 분기용으로 중요)
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((dest_ip, 80))
        ip = s.getsockname()[0]
    except:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip


# Linux: iptables REDIRECT된 TCP 소켓에서 원래 목적지(포트)를 얻기 위한 옵션
SO_ORIGINAL_DST = 80  # Linux constant

def get_original_dst_port(accepted_sock):
    """
    OUTPUT/PREROUTING REDIRECT로 들어온 소켓의 "원래 목적지 포트"를 읽는다.
    (예: 원래 9200/9300으로 가던 트래픽이 5020으로 꺾였을 때 분기용)
    """
    try:
        data = accepted_sock.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
        # sockaddr_in: family(2) + port(2) + addr(4) + zero(8)
        _family, port, _addr, _zero = struct.unpack("!HH4s8s", data)
        return int(port)
    except:
        return None


def sid32_from_hex(hex_str: str) -> bytes:
    """
    DB의 64-hex service_id를 32 bytes로 변환하고,
    혹시 짧거나 이상하면 padding/truncate로 32 bytes를 강제한다.
    """
    try:
        b = bytes.fromhex(hex_str)
    except:
        b = hex_str.encode('utf-8', errors='ignore')
    return b.ljust(32, b'\0')[:32]


# ==========================================
# [CLASS 1] AH 역할 (Inbound Traffic Handler)
# ==========================================
class SDP_Gateway_AH:
    def __init__(self):
        print(">>> [AH Role] 초기화 중...")
        cert_manager.ensure_device_cert("ah")
        self.client_ctx = make_client_ctx("ah")
        self.server_ctx = make_server_ctx("ah")

        self.my_ports = {"auth": 0, "data": 0}
        self.running = True
        self.controller_sock = None

        # service_id(32 bytes) -> (target_ip, target_port)
        self.service_map = {}

    def update_access_conf(self, source_name, enc, hmac, port):
        """방화벽 설정 파일 안전 업데이트 (Lock 사용)"""
        ts = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
        conf_block = (
            f"\n# TEMP {source_name} {ts}\n"
            f"SOURCE ANY\n"
            f"KEY_BASE64 {enc}\n"
            f"HMAC_KEY_BASE64 {hmac}\n"
            f"OPEN_PORTS tcp/{port}\n"
        )

        with file_lock:
            try:
                p = subprocess.Popen(
                    ['sudo', 'tee', '-a', FWKNOP_ACCESS_CONF],
                    stdin=subprocess.PIPE,
                    text=True
                )
                p.communicate(input=conf_block)
                subprocess.run(["sudo", "fwknopd", "-R"], check=False)

                # 자동 삭제 스케줄링(24h)
                del_cmd = (
                    f"sudo sed -i '/# TEMP {source_name} {ts}/,+5d' {FWKNOP_ACCESS_CONF}; "
                    f"sudo fwknopd -R"
                )
                subprocess.run(f"echo \"{del_cmd}\" | at now + 24 hours", shell=True)
                print(f"[AH] 방화벽 Open: tcp/{port} (for {source_name})")
            except Exception as e:
                print(f"[AH] 방화벽 설정 실패: {e}")

    def handle_auth_client(self, conn, addr):
        """
        Controller -> AH : 0x05 인증정보 전달
        AH는 받은 키로 'data_port(터널 종단 포트)'를 열어둔다.
        """
        try:
            cmd = recvall(conn, 1)
            if cmd and cmd[0] == 0x05:
                payload = recv_until_newline(conn)
                info = json.loads(payload)
                c = info['IH Authenticators'].get('credentials', {})
                self.update_access_conf("IH", c['spa_encryption_key'], c['spa_hmac_key'], self.my_ports['data'])
        except:
            pass
        finally:
            conn.close()

    def relay_target_to_tunnel(self, target_sock, ih_conn, ids):
        try:
            while self.running:
                data = target_sock.recv(4096)
                if not data:
                    break
                # 0x09 + Length + ID(32) + Session(32) + Data
                packet = struct.pack("!BH", 0x09, len(data)) + ids + data
                ih_conn.sendall(packet)
        except:
            pass
        finally:
            try:
                ih_conn.shutdown(socket.SHUT_WR)
            except:
                pass

    def handle_data_client(self, ih_conn, addr):
        """
        IH -> AH(data_port) 터널 종단.
        이 함수는 'service_id'로 내부 타깃(9200/9300 등)을 라우팅한다.
        """
        target_sock = None
        try:
            print(f"[AH-Data] IH 접속됨: {addr}")

            # 0x07 + (service_id32 + session32) = 65 bytes
            req = recvall(ih_conn, 65)
            if not req or req[0] != 0x07:
                return

            # OK 응답 (0x08 + 200 + IDs)
            ih_conn.sendall(struct.pack("!BH", 0x08, 200) + req[1:])
            ids = req[1:]
            svc_id = ids[:32]

            # ★ 핵심: service_id 기반 내부 라우팅
            target_ip, target_port = self.service_map.get(
                svc_id,
                (PROTECTED_TARGET_IP, PROTECTED_TARGET_PORT)  # fallback
            )

            try:
                target_sock = socket.create_connection((target_ip, target_port), timeout=5)
            except Exception as e:
                print(f"[AH] Target 연결 실패 ({target_ip}:{target_port}): {e}")
                return

            # Relay 시작 (target -> tunnel)
            t = threading.Thread(
                target=self.relay_target_to_tunnel,
                args=(target_sock, ih_conn, ids),
                daemon=True
            )
            t.start()

            # tunnel -> target
            while self.running:
                head = recvall(ih_conn, 3)
                if not head:
                    break
                cmd, ln = struct.unpack("!BH", head)

                if cmd == 0x09:
                    full_len = 64 + ln
                    payload = recvall(ih_conn, full_len)
                    if not payload:
                        break
                    real_data = payload[64:]
                    target_sock.sendall(real_data)

                elif cmd == 0x0A:
                    break

        except Exception as e:
            print(f"[AH-Data] Error: {e}")
        finally:
            if target_sock:
                try:
                    target_sock.close()
                except:
                    pass
            try:
                ih_conn.close()
            except:
                pass

    def start_listener(self, role, handler):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        bind_ip = AUTH_BIND_IP if role == "auth" else DATA_BIND_IP
        s.bind((bind_ip, 0))  # 랜덤 포트
        port = s.getsockname()[1]
        self.my_ports[role] = port

        s.listen(5)
        print(f"[AH Role] {role} Port Listening on: {bind_ip}:{port}")

        while self.running:
            try:
                conn, addr = s.accept()
                tls = self.server_ctx.wrap_socket(conn, server_side=True)
                threading.Thread(target=handler, args=(tls, addr), daemon=True).start()
            except:
                pass

    def _load_service_map_from_0x04(self, cmd_byte, payload_bytes):
        """
        Controller -> AH : 0x04 서비스 목록 수신
        {"services":[{"service_id":"..hex..","target_ip":"127.0.0.1","target_port":9200}, ...]}
        """
        if not cmd_byte or cmd_byte[0] != 0x04 or not payload_bytes:
            print("[AH] Warning: no service map received (0x04)")
            return

        try:
            info = json.loads(payload_bytes)
            self.service_map.clear()
            for s in info.get("services", []):
                sid = sid32_from_hex(s.get("service_id", ""))
                tip = s.get("target_ip", PROTECTED_TARGET_IP)
                tport = int(s.get("target_port", PROTECTED_TARGET_PORT))
                self.service_map[sid] = (tip, tport)
            print(f"[AH] service_map loaded: {len(self.service_map)} services")
        except Exception as e:
            print(f"[AH] service_map parse error: {e}")

    def run(self):
        # 1) 리스너 시작
        threading.Thread(target=self.start_listener, args=("auth", self.handle_auth_client), daemon=True).start()
        threading.Thread(target=self.start_listener, args=("data", self.handle_data_client), daemon=True).start()

        time.sleep(1)

        print(f"[AH Role] Controller({CONTROLLER_AH_PORT}) 접속 시도...")
        os.system(f"fwknop -n {CONTROLLER_IP} --fw-timeout 60 > /dev/null 2>&1")

        try:
            raw = socket.create_connection((CONTROLLER_IP, CONTROLLER_AH_PORT))
            self.controller_sock = self.client_ctx.wrap_socket(raw, server_hostname="sdp-controller")

            # Login (0x00)
            # ★ 변경: data_ip를 명시하여 Controller가 IH에게 data plane 주소를 내려주게 함
            login = {
                "device_id": "ah01",
                "data_port": self.my_ports['data'],
                "auth_port": self.my_ports['auth'],
                "data_ip": AH_DATA_IP or get_src_ip("192.168.100.1")  # fallback(권장 X)
            }
            self.controller_sock.sendall(bytes([0x00]) + json.dumps(login).encode('utf-8') + b'\n')

            # Login Response (0x01 + status + json\n)
            self.controller_sock.recv(3)
            resp = json.loads(recv_until_newline(self.controller_sock))
            print("[AH Role] Controller 로그인 성공")

            if 'controller_auth_keys' in resp:
                ck = resp['controller_auth_keys']
                # Controller -> AH(auth_port) 접속 허용(컨트롤 플레인)
                self.update_access_conf("Controller", ck['enc'], ck['hmac'], self.my_ports['auth'])

            # ★ 변경: 0x04 서비스 목록 수신 → service_map 구성
            cmd = self.controller_sock.recv(1)
            payload = recv_until_newline(self.controller_sock)
            self._load_service_map_from_0x04(cmd, payload)

            # Keep-Alive
            while self.running:
                if not self.controller_sock.recv(1):
                    break
                self.controller_sock.sendall(bytes([0x03]))

        except Exception as e:
            print(f"[AH Role] Error: {e}")
        finally:
            self.shutdown()

    def shutdown(self):
        self.running = False
        if self.controller_sock:
            try:
                print("[AH Role] 로그아웃(0x02) 전송")
                self.controller_sock.sendall(bytes([0x02]))
            except:
                pass
            try:
                self.controller_sock.close()
            except:
                pass


# ==========================================
# [CLASS 2] IH 역할 (Outbound Traffic Handler)
# ==========================================
class SDP_Gateway_IH:
    def __init__(self):
        print(">>> [IH Role] 초기화 중...")
        cert_manager.ensure_device_cert("ih")
        self.client_ctx = make_client_ctx("ih")
        self.running = True
        self.controller_sock = None
        self.proxy_listener = None

    def relay_local_to_tunnel(self, local_sock, tunnel_sock, ids):
        try:
            while True:
                data = local_sock.recv(4096)
                if not data:
                    break
                packet = struct.pack("!BH", 0x09, len(data)) + ids + data
                tunnel_sock.sendall(packet)
        except:
            pass
        finally:
            try:
                tunnel_sock.shutdown(socket.SHUT_WR)
            except:
                pass

    def relay_tunnel_to_local(self, tunnel_sock, local_sock):
        try:
            while True:
                head = recvall(tunnel_sock, 3)
                if not head:
                    break
                cmd, ln = struct.unpack("!BH", head)

                if cmd == 0x09:
                    full_len = 64 + ln
                    payload = recvall(tunnel_sock, full_len)
                    if not payload:
                        break
                    local_sock.sendall(payload[64:])
                elif cmd == 0x0A:
                    break
        except:
            pass
        finally:
            try:
                local_sock.close()
            except:
                pass

    def start_proxy_service(self, svc_by_port, sess, spa_enc, spa_hmac):
        """
        ★ 변경: 단일 프록시(5020)로 들어오는 연결을,
        '원래 목적지 포트(예: 9200/9300)' 기준으로 서비스(service_id)를 선택한다.
        """
        try:
            self.proxy_listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.proxy_listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.proxy_listener.bind((LOCAL_PROXY_IP, LOCAL_PROXY_PORT))
            self.proxy_listener.listen(50)

            print(f"\n[IH Role] Proxy Started on {LOCAL_PROXY_IP}:{LOCAL_PROXY_PORT}")
            print(f"[IH Role] Service Ports: {list(svc_by_port.keys())}")
            print("[IH Role] Ready for connection... (Listening)")

            while self.running:
                user_sock, user_addr = self.proxy_listener.accept()

                # ★ 핵심: 원래 목적지 포트(9200/9300) 추출
                orig_port = get_original_dst_port(user_sock)
                svc = svc_by_port.get(orig_port)

                if not svc:
                    print(f"[IH Role] Drop: no service for orig_port={orig_port} from {user_addr}")
                    try:
                        user_sock.close()
                    except:
                        pass
                    continue

                target_ip = svc['address']       # AH data_ip
                tunnel_port = svc['port']        # AH data_port(터널 종단 포트)

                print(f"[IH Role] New Conn {user_addr} orig_dport={orig_port} -> {svc['name']} via {target_ip}:{tunnel_port}")

                # SPA (fwknop): data_port 열기
                my_ip = get_src_ip(target_ip)
                fwknop_cmd = (
                    f"/usr/bin/fwknop -A tcp/{tunnel_port} --fw-timeout 1800 --use-hmac "
                    f"--key-base64-rijndael '{spa_enc}' --key-base64-hmac '{spa_hmac}' "
                    f"-D {target_ip} -a {my_ip} -R"
                )
                os.system(fwknop_cmd + " > /dev/null 2>&1")
                time.sleep(1.2)

                # Tunnel Connect
                raw = socket.create_connection((target_ip, tunnel_port), timeout=5)
                tunnel_sock = self.client_ctx.wrap_socket(raw, server_hostname="sdp-ah")

                # Handshake: 0x07 + service_id32 + session32
                svc_id_bytes = sid32_from_hex(svc['id'])
                ids = (svc_id_bytes + sess.encode().ljust(32, b'\0')[:32])
                tunnel_sock.sendall(bytes([0x07]) + ids)

                if not recvall(tunnel_sock, 67):
                    try:
                        user_sock.close()
                    except:
                        pass
                    try:
                        tunnel_sock.close()
                    except:
                        pass
                    continue

                # Start Relay
                t1 = threading.Thread(target=self.relay_local_to_tunnel, args=(user_sock, tunnel_sock, ids), daemon=True)
                t2 = threading.Thread(target=self.relay_tunnel_to_local, args=(tunnel_sock, user_sock), daemon=True)
                t1.start()
                t2.start()

        except Exception as e:
            print(f"[IH Proxy] Listener Error: {e}")
        finally:
            if self.proxy_listener:
                try:
                    self.proxy_listener.close()
                except:
                    pass

    def run(self):
        self.running = True

        print(f"[IH Role] Controller({CONTROLLER_IH_PORT}) 접속 시도...")
        os.system(f"fwknop -n {CONTROLLER_IP} --fw-timeout 60 > /dev/null 2>&1")
        time.sleep(1)

        try:
            raw = socket.create_connection((CONTROLLER_IP, CONTROLLER_IH_PORT))
            self.controller_sock = self.client_ctx.wrap_socket(raw, server_hostname="sdp-controller")

            # Login
            self.controller_sock.sendall(bytes([0x00]))
            self.controller_sock.recv(3)
            login = json.loads(recv_until_newline(self.controller_sock))
            print("[IH Role] Controller 로그인 성공")

            # Keep-Alive
            self.controller_sock.sendall(bytes([0x03]))
            self.controller_sock.recv(1)

            # Service Info
            cmd = self.controller_sock.recv(1)
            if cmd and cmd[0] == 0x06:
                info = json.loads(recv_until_newline(self.controller_sock))
                services = info.get('services', [])

                if not services:
                    print("[IH Role] 사용 가능한 서비스가 없습니다.")
                    return

                # ★ 변경: target_port(9200/9300) 기준 맵 구성
                svc_by_port = {}
                for s in services:
                    tp = s.get("target_port")
                    if tp is not None:
                        svc_by_port[int(tp)] = s

                print(f"[IH Role] 서비스 맵 구성 완료: {list(svc_by_port.keys())}")

                # Controller 연결 끊기 전 로그아웃
                print("[IH Role] 로그아웃(0x07) 전송 후 프록시 모드 진입")
                try:
                    self.controller_sock.sendall(bytes([0x07]))
                except:
                    pass
                try:
                    self.controller_sock.close()
                except:
                    pass
                self.controller_sock = None

                self.start_proxy_service(
                    svc_by_port,
                    login['session_id'],
                    login['credentials']['spa_encryption_key'],
                    login['credentials']['spa_hmac_key']
                )

        except Exception as e:
            print(f"[IH Role] Error: {e}")
        finally:
            if self.controller_sock:
                try:
                    self.controller_sock.sendall(bytes([0x07]))
                except:
                    pass
                try:
                    self.controller_sock.close()
                except:
                    pass

    def shutdown(self):
        self.running = False
        if self.proxy_listener:
            try:
                self.proxy_listener.close()
            except:
                pass
        print("[IH Role] Shutdown signal received.")


# ==========================================
# [Main] 통합 실행 (Menu Driven)
# ==========================================
def main():
    print("=== SDP Unified Gateway Started (Interactive Mode) ===")

    # AH 모듈(항상 실행)
    ah_module = SDP_Gateway_AH()
    t_ah = threading.Thread(target=ah_module.run, daemon=True)
    t_ah.start()
    print("[System] AH Module started in background. (Logs will appear below)")

    # IH 모듈(옵션 실행)
    ih_module = SDP_Gateway_IH()
    t_ih = None

    while True:
        try:
            print("\n--------------------------------")
            print("   SDP Gateway Control Panel")
            print("--------------------------------")
            print("1. Start IH (Connect & Proxy)")
            print("2. Stop IH")
            print("0. Exit Gateway")

            cmd = input("Select > ").strip()

            if cmd == '1':
                if t_ih and t_ih.is_alive():
                    print("[System] IH is already running!")
                else:
                    print("[System] Starting IH Module...")
                    t_ih = threading.Thread(target=ih_module.run, daemon=True)
                    t_ih.start()

            elif cmd == '2':
                if t_ih and t_ih.is_alive():
                    print("[System] Stopping IH Module...")
                    ih_module.shutdown()
                    t_ih.join(timeout=2)
                    print("[System] IH Stopped.")
                else:
                    print("[System] IH is not running.")

            elif cmd == '0':
                print("[System] Shutting down everything...")
                ah_module.shutdown()
                if t_ih and t_ih.is_alive():
                    ih_module.shutdown()
                print("Bye!")
                break

            else:
                print("[System] Invalid command.")

        except KeyboardInterrupt:
            print("\n[System] Force Exit detected.")
            break
        except Exception as e:
            print(f"[System] Menu Error: {e}")


if __name__ == '__main__':
    main()
