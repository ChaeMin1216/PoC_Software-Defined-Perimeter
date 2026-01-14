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
    
    print(f"[AH] 방화벽 설정 업데이트 ({source_name} -> Port {port})...")
    try:
        p = subprocess.Popen(['sudo', 'tee', '-a', CONFIG_FILE], stdin=subprocess.PIPE, text=True)
        p.communicate(input=conf_block)
        subprocess.run(["sudo", "fwknopd", "-R"], check=False)
        
        del_cmd = f"sudo sed -i '/# TEMP {source_name} {ts}/,+5d' {CONFIG_FILE}; sudo fwknopd -R"
        subprocess.run(f"echo \"{del_cmd}\" | at now + 24 hours", shell=True)
    except Exception as e:
        print(f"[AH] 방화벽 설정 실패: {e}")

def handle_auth(conn, addr):
    try:
        cmd = conn.recv(1)
        if cmd and cmd[0] == 0x05:
            payload = recv_until_newline(conn)
            info = json.loads(payload)
            print(f"[AH-Auth] Controller 승인 수신. IH 키 등록 중...")
            
            c = info['IH Authenticators'].get('credentials', {})
            update_access_conf("IH", c['spa_encryption_key'], c['spa_hmac_key'], my_ports['data'])
            print("[DBG] AH에 등록되는 IH 키:", c['spa_encryption_key'], c['spa_hmac_key'])
    except Exception as e: print(f"[AH-Auth] Err: {e}")
    finally: conn.close()

def handle_data(conn, addr):
    try:
        print(f"[AH-Data] IH 접속됨: {addr}")
        req = conn.recv(65)
        if req and req[0] == 0x07:
            conn.sendall(struct.pack("!BH", 0x08, 200) + req[1:])
            while True:
                head = conn.recv(3)
                if not head: break
                cmd, ln = struct.unpack("!BH", head)
                if cmd == 0x09:
                    body = conn.recv(64 + ln)
                    print(f"[AH-Data] 수신: {body[64:].decode()}")
                    conn.sendall(head + body)
                elif cmd == 0x0A: break
    except: pass
    finally: conn.close()

def start_dynamic_server(role, handler):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('0.0.0.0', 0))
    port = s.getsockname()[1]
    my_ports[role] = port
    s.listen(5)
    print(f"[AH] {role} 서버 리스닝: {port}")
    while True:
        try:
            conn, addr = s.accept()
            tls = SERVER_CTX.wrap_socket(conn, server_side=True)
            threading.Thread(target=handler, args=(tls, addr), daemon=True).start()
        except: pass

def main():
    threading.Thread(target=start_dynamic_server, args=("auth", handle_auth), daemon=True).start()
    threading.Thread(target=start_dynamic_server, args=("data", handle_data), daemon=True).start()
    #time.sleep(0.5)

    print(f"[AH] Controller({CONTROLLER_PORT})에 SPA 전송...")
    os.system(f"fwknop -n {CONTROLLER_IP} --fw-timeout 60")
    #time.sleep(1)

    try:
        raw = socket.create_connection((CONTROLLER_IP, CONTROLLER_PORT))
        sock = CLIENT_CTX.wrap_socket(raw, server_hostname="sdp-controller")
        
        login = {"device_id": "ah01", "data_port": my_ports['data'], "auth_port": my_ports['auth']}
        sock.sendall(bytes([0x00]) + json.dumps(login).encode('utf-8') + b'\n')
        
        head = sock.recv(3)
        payload = recv_until_newline(sock)
        resp = json.loads(payload)
        print("[AH] Controller 로그인 완료")
        
        if 'controller_auth_keys' in resp:
            ck = resp['controller_auth_keys']
            update_access_conf("Controller", ck['enc'], ck['hmac'], my_ports['auth'])

        sock.recv(1); recv_until_newline(sock) # Ack

        while True:
            if not sock.recv(1): break
            sock.sendall(bytes([0x03]))
    except Exception as e: print(f"[AH] 연결 실패: {e}")

if __name__ == '__main__':
    main()
