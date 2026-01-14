#!/usr/bin/env python3
import socket
import struct
import json
import time
import sys
import os
import subprocess
import threading
import signal
from tls_util import make_client_ctx
import cert_manager

# ==========================================
# [설정] IH가 로컬에서 열 포트
# ==========================================
LOCAL_BIND_IP = '127.0.0.1'
LOCAL_BIND_PORT = 5020

print(">>> [IH] 인증서 확인...")
cert_manager.ensure_device_cert("ih")
print(">>> [IH] 준비 완료\n")

CONTROLLER_IP = '192.168.163.129'
CONTROLLER_PORT = 4433
CLIENT_CTX = make_client_ctx("ih")

# 전역 변수로 리스너 선언 (Ctrl+C 종료 시 닫기 위해)
server_listener = None

def recv_until_newline(sock):
    data = b''
    while True:
        try:
            chunk = sock.recv(1)
            if not chunk: return None
            data += chunk
            if chunk == b'\n': break
        except: return None
    return data

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((CONTROLLER_IP, 80))
        ip = s.getsockname()[0]
    except: ip = "127.0.0.1"
    finally: s.close()
    return ip

# -------------------------------------------------------
# [Proxy] 로컬 앱 -> 터널
# -------------------------------------------------------
def relay_local_to_tunnel(local_sock, tunnel_sock, ids):
    try:
        while True:
            data = local_sock.recv(4096)
            if not data: break
            packet = struct.pack("!BH", 0x09, len(data)) + ids + data
            tunnel_sock.sendall(packet)
    except Exception:
        pass # 연결 종료는 자연스러운 현상이므로 에러 출력 생략
    finally:
        try: tunnel_sock.shutdown(socket.SHUT_WR)
        except: pass

# -------------------------------------------------------
# [Proxy] 터널 -> 로컬 앱
# -------------------------------------------------------
def relay_tunnel_to_local(tunnel_sock, local_sock):
    try:
        while True:
            head = tunnel_sock.recv(3)
            if not head: break
            cmd, ln = struct.unpack("!BH", head)
            
            if cmd == 0x09:
                full_len = 64 + ln
                payload = b''
                while len(payload) < full_len:
                    chunk = tunnel_sock.recv(full_len - len(payload))
                    if not chunk: break
                    payload += chunk
                
                if len(payload) < 64: break
                local_sock.sendall(payload[64:])
            elif cmd == 0x0A:
                break
    except Exception:
        pass
    finally:
        try: local_sock.close()
        except: pass

def start_proxy_service(svc, sess, spa_enc, spa_hmac):
    """
    무한 루프를 돌며 사용자의 접속을 기다리고,
    접속이 오면 그때 AH와 터널을 연결합니다.
    """
    global server_listener
    target_ip = svc['address']
    target_port = svc['port']

    try:
        server_listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_listener.bind((LOCAL_BIND_IP, LOCAL_BIND_PORT))
        server_listener.listen(5) # 동시 접속 대기열

        print(f"\n[IH] Gateway Started on {LOCAL_BIND_IP}:{LOCAL_BIND_PORT}")
        print(f"[IH] Target Service: {svc['name']} ({target_ip}:{target_port})")
        print("[IH] Press Ctrl+C to stop safely.\n")

        while True:
            try:
                # 1. 사용자 접속 대기 (여기서 멈춰있음)
                print(f"[Ready] Waiting for connection...")
                user_sock, user_addr = server_listener.accept()
                print(f"[New Connection] {user_addr} -> Establishing Tunnel...")

                # 2. 사용자 접속 시 SPA 전송 (On-Demand)
                my_ip = get_local_ip()
                # IP 자동 감지 실패 시 수동 IP 사용 
                # my_ip = "192.168.163.131"

                fwknop_cmd = (
                    f"/usr/bin/fwknop -A tcp/{target_port} "
                    f"--fw-timeout 1800 --use-hmac "
                    f"--key-base64-rijndael '{spa_enc}' "
                    f"--key-base64-hmac '{spa_hmac}' "
                    f"-D {target_ip} -a {my_ip} -R"
                )
                
                # 조용히 실행 (로그 너무 많이 뜨지 않게)
                ret = os.system(fwknop_cmd + " > /dev/null 2>&1")
                if ret != 0:
                    print("[Error] FWKNOP Failed.")
                    user_sock.close()
                    continue

                # AH가 방화벽 열 시간 잠깐 대기
                time.sleep(1.5)

                # 3. AH와 터널 연결
                raw = socket.create_connection((target_ip, target_port), timeout=5)
                tunnel_sock = CLIENT_CTX.wrap_socket(raw, server_hostname="sdp-ah")

                # Handshake
                ids = (bytes.fromhex(svc['id']) + sess.encode().ljust(32, b'\0')[:32])
                tunnel_sock.sendall(bytes([0x07]) + ids)

                if not tunnel_sock.recv(67):
                    print("[Error] AH Handshake Failed")
                    user_sock.close()
                    tunnel_sock.close()
                    continue

                print(f"[Tunnel Open] Relay Started for {user_addr}")

                # 4. 데이터 릴레이 (스레드 생성)
                t1 = threading.Thread(target=relay_local_to_tunnel, args=(user_sock, tunnel_sock, ids))
                t2 = threading.Thread(target=relay_tunnel_to_local, args=(tunnel_sock, user_sock))
                
                # 데몬 스레드로 설정 (Ctrl+C 시 함께 종료되도록)
                t1.daemon = True
                t2.daemon = True
                
                t1.start()
                t2.start()

                # 주의: join()을 하지 않고 루프로 돌아가야 다음 사람을 받을 수 있음
                # 하지만 현재 구조는 간단한 구현을 위해 join()을 하여 "한 번에 한 명씩" 처리하는게 안전함
                # (여러 명이 동시에 쓰려면 소켓 관리가 더 복잡해짐)
                t1.join()
                t2.join()
                
                print(f"[Closed] Session finished for {user_addr}\n")

            except socket.timeout:
                print("[Timeout] AH did not respond.")
            except KeyboardInterrupt:
                raise # 밖으로 던져서 종료 처리
            except Exception as e:
                print(f"[Error] {e}")

    except KeyboardInterrupt:
        print("\n\n>>> [IH] Stopping Gateway (Ctrl+C detected)...")
    finally:
        if server_listener:
            server_listener.close()
        print(">>> [IH] Gateway Stopped. Bye!")

def main():
    print(f"[IH] Controller({CONTROLLER_IP}) 접속 중...")
    os.system(f"fwknop -n {CONTROLLER_IP} --fw-timeout 60 > /dev/null 2>&1")
    time.sleep(1)

    sock = None
    try:
        raw = socket.create_connection((CONTROLLER_IP, CONTROLLER_PORT), timeout=5)
        sock = CLIENT_CTX.wrap_socket(raw, server_hostname="sdp-controller")

        # 1. 로그인 요청 (0x00)
        sock.sendall(bytes([0x00])) 
        sock.recv(3)
        login = json.loads(recv_until_newline(sock))
        print("[IH] Controller 로그인 성공")

        # 2. Keep-Alive (0x03)
        sock.sendall(bytes([0x03])) 
        sock.recv(1)

        # 3. 서비스 정보 수신 (0x06)
        cmd = sock.recv(1) 
        if cmd and cmd[0] == 0x06:
            info = json.loads(recv_until_newline(sock))
            if info.get('services'):
                tgt = info['services'][0]
                
                # [추가됨] Controller와 연결을 끊기 전에 명세 준수를 위해 로그아웃(0x07) 전송
                print("[IH] Controller에게 로그아웃(0x07) 전송 후 프록시 모드 전환")
                try:
                    sock.sendall(bytes([0x07])) # [cite: 129]
                except: pass
                
                # 정보만 받고 소켓은 닫음 (Controller와 연결 끊고 Proxy 전념)
                sock.close()
                sock = None # 소켓 객체 해제
                
                # 무한 루프 프록시 서비스 시작
                start_proxy_service(
                    tgt, login['session_id'],
                    login['credentials']['spa_encryption_key'],
                    login['credentials']['spa_hmac_key']
                )
                return

        # 서비스가 없거나 정상 종료 시에도 로그아웃 전송
        try:
            sock.sendall(bytes([0x07]))
        except: pass
        sock.close()

    except KeyboardInterrupt:
        print("\n>>> [IH] Cancelled by user.")
        # 강제 종료 시에도 가능하면 로그아웃 시도
        if sock:
            try: sock.sendall(bytes([0x07]))
            except: pass
            sock.close()
    except Exception as e:
        print(f"[IH] Main Error: {e}")
        if sock: sock.close()

if __name__ == '__main__':
    main()
