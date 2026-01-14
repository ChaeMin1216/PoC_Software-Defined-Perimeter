#!/usr/bin/env python3
import socket
import struct
import json
import time
import threading
import sys
import os
import subprocess
from tls_util import make_server_ctx, make_client_ctx
import cert_manager
import hashlib

# [Factory Config]
#BOOTSTRAP_KEY = "MacWBSG049j+C+F4/qfVnQ=="
#BOOTSTRAP_HMAC = "MyHMACKeyForBootstrap123=="
ACCESS_CONF = "/etc/fwknop/access.conf"

print(">>> [Controller] 인증서 확인...")
cert_manager.ensure_device_cert("controller")
print(">>> [Controller] 준비 완료\n")

#def setup_bootstrap_access():
#    try:
#        with open(ACCESS_CONF, 'r') as f:
#            if BOOTSTRAP_KEY in f.read(): return
#        print(">>> [System] 공장 초기화 키 등록 중...")
#        stanza = f"\nSOURCE ANY\nOPEN_PORTS tcp/4433,tcp/4444\nKEY_BASE64 {BOOTSTRAP_KEY}\nHMAC_KEY_BASE64 {BOOTSTRAP_HMAC}\n"
#        p = subprocess.Popen(['sudo', 'tee', '-a', ACCESS_CONF], stdin=subprocess.PIPE, text=True)
#        p.communicate(input=stanza)
#        os.system("sudo fwknopd -R")
#    except: pass

#setup_bootstrap_access()

BIND_IP = '0.0.0.0'
IH_PORT = 4433
AH_PORT = 4444

ah_registry = {}
SERVER_CTX = make_server_ctx("controller")
CLIENT_CTX_TO_AH = make_client_ctx("controller")

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

def get_fwknop_keys():
    try:
        output = subprocess.check_output(["fwknop", "--key-gen"], stderr=subprocess.STDOUT)
        out_str = output.decode("utf-8")
        enc, hmac = None, None
        for line in out_str.splitlines():
            if line.startswith("KEY_BASE64:"): enc = line.split(":", 1)[1].strip()
            elif line.startswith("HMAC_KEY_BASE64:"): hmac = line.split(":", 1)[1].strip()
        if enc and hmac: return enc, hmac
        raise Exception("Key Parse Error")
    except: return "def_enc", "def_hmac"

def update_local_fwknoprc(target_ip, target_port, enc, hmac):
    rc = os.path.expanduser("~/.fwknoprc")
    stanza = f"\n[{target_ip}]\nALLOW_IP 0.0.0.0\nACCESS tcp/{target_port}\nSPA_SERVER {target_ip}\nKEY_BASE64 {enc}\nHMAC_KEY_BASE64 {hmac}\nUSE_HMAC Y\n"
    try:
        with open(rc, "a") as f: f.write(stanza)
        os.chmod(rc, 0o600)
    except: pass

def send_auth_to_ah(ip, port, info):
    """AH에게 키 정보를 전송 (동기식으로 변경됨)"""
    try:
        print(f"[Controller] 1단계: AH({ip}:{port})에게 키 배포 시도...")
        os.system(f"fwknop -A tcp/{port} --fw-timeout 60 -n {ip}")
        time.sleep(1.5) # AH가 SPA 처리할 시간 확보
        
        raw = socket.create_connection((ip, port), timeout=5)
        sock = CLIENT_CTX_TO_AH.wrap_socket(raw, server_hostname="sdp-ah")
        sock.sendall(bytes([0x05]) + json.dumps(info).encode('utf-8') + b'\n')
        sock.close()
        print(f"[Controller] AH에게 키 배포 성공.")
        return True
    except Exception as e: 
        print(f"[Controller] AH 전송 실패: {e}")
        return False

def handle_ih(conn, addr):
    print(f"[Controller-IH] IH 접속: {addr}")
    try:
        if not conn.recv(1): return
        print("[Controller-IH] 로그인 요청 수신")
        
        sess_id = os.urandom(32).hex()
        enc, hmac = get_fwknop_keys() # IH-AH 전용 키 생성
        
        # 1. Login Resp
        resp = {"session_id": sess_id, "credentials": {"spa_encryption_key": enc, "spa_hmac_key": hmac}}
        conn.sendall(struct.pack("!BH", 0x01, 200) + json.dumps(resp).encode('utf-8') + b'\n')
        
        if conn.recv(1): conn.sendall(bytes([0x03]))

        # ★ [수정됨] 2. AH에게 먼저 키를 등록시킴 (동기식)
        # AH가 준비되어야 IH가 접속할 수 있으므로 여기서 Blocking으로 처리
        auth_info = {"IH Authenticators": {"IH": f"IH_{addr[0]}", "credentials": {"spa_encryption_key": enc, "spa_hmac_key": hmac}}}
        
        ah_ready_count = 0
        for info in ah_registry.values():
            # 스레드 대신 직접 호출하여 순서 보장
            if send_auth_to_ah(info['ip'], info['auth_port'], auth_info):
                ah_ready_count += 1
        
        print(f"[Controller] AH 준비 완료 ({ah_ready_count}대). 이제 IH에게 목록 전송.")
        service_id_256 = os.urandom(32).hex()
        # 3. AH가 준비된 후 서비스 목록 전송 (0x06)
        svcs = [{"id": service_id_256, "name": "PLC", "type": "TCP", "address": v['ip'], "port": v['data_port']} for v in ah_registry.values()]
        conn.sendall(bytes([0x06]) + json.dumps({"services": svcs}).encode('utf-8') + b'\n')
        print(f"[Controller-IH] 서비스 목록 전송 완료")
        print("[DBG] IH 키:", enc, hmac)


        while True:
            cmd = conn.recv(1)
            if not cmd or cmd[0] == 0x07: break
            if cmd[0] == 0x03: conn.sendall(bytes([0x03]))
            
    except Exception as e: print(f"[IH-Error] {e}")
    finally: conn.close()

def handle_ah(conn, addr):
    print(f"[Controller-AH] AH 접속: {addr}")
    sess = None
    try:
        if not conn.recv(1): return
        req = json.loads(recv_until_newline(conn))
        
        sess = os.urandom(16).hex()
        ah_registry[sess] = {"ip": addr[0], "data_port": req['data_port'], "auth_port": req['auth_port']}
        print(f"[Controller-AH] 등록됨 (Ports: {req['data_port']}, {req['auth_port']})")

        # Controller -> AH 접속용 키 생성 및 교환
        c_enc, c_hmac = get_fwknop_keys()
        update_local_fwknoprc(addr[0], req['auth_port'], c_enc, c_hmac)
        
        resp = {
            "session_id": sess,
            "controller_auth_keys": {"enc": c_enc, "hmac": c_hmac}
        }
        conn.sendall(struct.pack("!BH", 0x01, 200) + json.dumps(resp).encode('utf-8') + b'\n')
        conn.sendall(bytes([0x04]) + json.dumps({"services": []}).encode('utf-8') + b'\n')

        while True:
            if not conn.recv(1): break
            conn.sendall(bytes([0x03]))
    except: pass
    finally:
        if sess in ah_registry: del ah_registry[sess]
        conn.close()

def serve(port, handler):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((BIND_IP, port))
    s.listen(5)
    while True:
        try:
            c, a = s.accept()
            t = SERVER_CTX.wrap_socket(c, server_side=True)
            threading.Thread(target=handler, args=(t, a)).start()
        except: pass

if __name__ == '__main__':
    threading.Thread(target=serve, args=(IH_PORT, handle_ih), daemon=True).start()
    threading.Thread(target=serve, args=(AH_PORT, handle_ah), daemon=True).start()
    print("[Controller] 서버 가동 중 (SPA 보호됨)...")
    while True: time.sleep(1)
