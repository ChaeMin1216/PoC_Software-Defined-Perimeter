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
from tls_util import make_client_ctx, make_server_ctx
import cert_manager

# ==========================================
# [설정] AH가 보호하는 실제 목적지 (PLC, Web Server 등)
# Gateway Mode라면 외부 PLC IP, Agent Mode라면 localhost
# ==========================================
REAL_TARGET_IP = '127.0.0.1' 
REAL_TARGET_PORT = 80  # 예: 웹서버(80), PLC(502), SSH(22)

print(">>> [AH] 인증서 확인...")
cert_manager.ensure_device_cert("ah")
print(">>> [AH] 준비 완료\n")

CONTROLLER_IP = '192.168.163.129'
CONTROLLER_PORT = 4444
CONFIG_FILE = "/etc/fwknop/access.conf"

CLIENT_CTX = make_client_ctx("ah")
SERVER_CTX = make_server_ctx("ah")
my_ports = {"auth": 0, "data": 0}

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

def update_access_conf(source_name, enc, hmac, port):
    ts = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
    conf_block = f"\n# TEMP {source_name} {ts}\nSOURCE ANY\nKEY_BASE64 {enc}\nHMAC_KEY_BASE64 {hmac}\nOPEN_PORTS tcp/{port}\n"
    try:
        p = subprocess.Popen(['sudo', 'tee', '-a', CONFIG_FILE], stdin=subprocess.PIPE, text=True)
        p.communicate(input=conf_block)
        subprocess.run(["sudo", "fwknopd", "-R"], check=False)
        del_cmd = f"sudo sed -i '/# TEMP {source_name} {ts}/,+5d' {CONFIG_FILE}; sudo fwknopd -R"
        subprocess.run(f"echo \"{del_cmd}\" | at now + 24 hours", shell=True)
        print(f"[AH] 방화벽 Open: tcp/{port} (for {source_name})")
    except Exception as e:
        print(f"[AH] 방화벽 설정 실패: {e}")

def handle_auth(conn, addr):
    try:
        cmd = conn.recv(1)
        if cmd and cmd[0] == 0x05:
            payload = recv_until_newline(conn)
            info = json.loads(payload)
            c = info['IH Authenticators'].get('credentials', {})
            update_access_conf("IH", c['spa_encryption_key'], c['spa_hmac_key'], my_ports['data'])
    except: pass
    finally: conn.close()

# -------------------------------------------------------
# [Proxy] 실제 타겟(PLC) -> 터널(IH)로 응답 전송
# -------------------------------------------------------
def relay_target_to_tunnel(target_sock, ih_conn, ids):
    try:
        while True:
            data = target_sock.recv(4096)
            if not data: break
            
            # AH->IH 패킷 포맷: [CMD 0x09] [LEN] [ID] [DATA]
            # ID는 받은 것을 그대로 사용 (규격 준수)
            packet = struct.pack("!BH", 0x09, len(data)) + ids + data
            ih_conn.sendall(packet)
    except: pass
    finally:
        try: ih_conn.shutdown(socket.SHUT_WR)
        except: pass

def handle_data(ih_conn, addr):
    target_sock = None
    try:
        print(f"[AH-Data] IH 접속됨: {addr}")
        
        # 1. 인증 헤더(0x07) 확인
        req = ih_conn.recv(65)
        if not req or req[0] != 0x07: return
        
        # 2. OK 응답
        ih_conn.sendall(struct.pack("!BH", 0x08, 200) + req[1:])
        ids = req[1:] # 세션 ID 저장

        # 3. 실제 타겟 연결 시도
        try:
            target_sock = socket.create_connection((REAL_TARGET_IP, REAL_TARGET_PORT), timeout=5)
            print(f"[AH] Target({REAL_TARGET_IP}:{REAL_TARGET_PORT}) 연결 성공")
        except Exception as e:
            print(f"[AH] Target 연결 실패: {e}")
            return

        # 4. 타겟 -> 터널 방향 스레드 시작
        t = threading.Thread(target=relay_target_to_tunnel, args=(target_sock, ih_conn, ids), daemon=True)
        t.start()

        # 5. 터널 -> 타겟 방향 (Main Loop)
        while True:
            head = ih_conn.recv(3)
            if not head: break
            
            cmd, ln = struct.unpack("!BH", head)
            
            if cmd == 0x09: # 데이터
                full_len = 64 + ln
                payload = b''
                while len(payload) < full_len:
                    chunk = ih_conn.recv(full_len - len(payload))
                    if not chunk: break
                    payload += chunk
                
                if len(payload) < 64: break
                
                # ID 떼고 실제 데이터만 타겟으로 전송
                real_data = payload[64:]
                target_sock.sendall(real_data)
                
            elif cmd == 0x0A: # 종료
                break

    except Exception as e:
        print(f"[AH-Data] Error: {e}")
    finally:
        print(f"[AH] 세션 종료: {addr}")
        if target_sock: target_sock.close()
        ih_conn.close()

def start_dynamic_server(role, handler):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('0.0.0.0', 0))
    port = s.getsockname()[1]
    my_ports[role] = port
    s.listen(5)
    print(f"[AH] {role} Port: {port}")
    while True:
        try:
            conn, addr = s.accept()
            tls = SERVER_CTX.wrap_socket(conn, server_side=True)
            threading.Thread(target=handler, args=(tls, addr), daemon=True).start()
        except: pass

def main():
    # 인증 및 데이터 처리 서버 스레드 시작
    threading.Thread(target=start_dynamic_server, args=("auth", handle_auth), daemon=True).start()
    threading.Thread(target=start_dynamic_server, args=("data", handle_data), daemon=True).start()
    
    print(f"[AH] Controller({CONTROLLER_PORT}) 연결 중...")
    # Controller 방화벽 Open 요청 (SPA)
    os.system(f"fwknop -n {CONTROLLER_IP} --fw-timeout 60")
    
    sock = None
    try:
        raw = socket.create_connection((CONTROLLER_IP, CONTROLLER_PORT))
        sock = CLIENT_CTX.wrap_socket(raw, server_hostname="sdp-controller")
        
        # 1. 로그인 요청 (0x00)
        login = {"device_id": "ah01", "data_port": my_ports['data'], "auth_port": my_ports['auth']}
        sock.sendall(bytes([0x00]) + json.dumps(login).encode('utf-8') + b'\n')
        
        # 2. 로그인 응답 수신 (0x01)
        sock.recv(3) # Header skip
        resp = json.loads(recv_until_newline(sock))
        print("[AH] Controller 로그인 완료")
        
        # Controller가 접속할 수 있도록 방화벽 설정 업데이트
        if 'controller_auth_keys' in resp:
            ck = resp['controller_auth_keys']
            update_access_conf("Controller", ck['enc'], ck['hmac'], my_ports['auth'])

        # 3. 서비스 목록 수신 대기 (0x04 - AH는 빈 목록을 받음)
        sock.recv(1); recv_until_newline(sock)

        # 4. Keep-Alive 루프 (0x03)
        while True: 
            if not sock.recv(1): break
            sock.sendall(bytes([0x03]))

    except KeyboardInterrupt:
        print("\n[AH] 종료 요청 (Ctrl+C)")
    except Exception as e: 
        print(f"[AH] Fail: {e}")
    finally:
        # ★ [추가됨] 명세 준수: 로그아웃 메시지 (0x02) 전송
        if sock:
            try:
                print("[AH] Controller에게 로그아웃(0x02) 전송")
                sock.sendall(bytes([0x02])) # [cite: 44]
            except: pass
            sock.close()
        print("[AH] 종료 완료")
        
if __name__ == '__main__':
    main()
