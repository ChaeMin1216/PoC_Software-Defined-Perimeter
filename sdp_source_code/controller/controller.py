#!/usr/bin/env python3
import socket
import struct
import json
import time
import threading
import sys
import os
import subprocess
import sqlite3
import hashlib
from tls_util import make_server_ctx, make_client_ctx
import cert_manager

# ==========================================
# [설정]
# ==========================================
# NOTE:
# - 컨트롤 플레인(172.16.x.x)만 바인딩하고 싶으면 BIND_IP를 172.16 컨트롤러 IP로 고정하는 것이 가장 확실함.
# - 여기서는 기존과 호환되도록 0.0.0.0 유지.
BIND_IP = '0.0.0.0'
IH_PORT = 4433
AH_PORT = 4444
DB_FILE = "sdp_controller.db"

# [메모리 캐시] 현재 접속 중인 AH의 실시간 위치 정보
# format:
# {
#   "device_id": {
#       "mgmt_ip": "...(컨트롤 플레인: 172.16...)",
#       "data_ip": "...(데이터 플레인: 192.168.100...)",
#       "auth_port": 1234,     # AH auth(mTLS) 리슨 포트(컨트롤 플레인에서 접근)
#       "data_port": 5678,     # AH data(mTLS) 리슨 포트(데이터 플레인에서 접근)
#       "session": "..."
#   }
# }
active_gateways = {}

print(">>> [Controller] 인증서 확인...")
cert_manager.ensure_device_cert("controller")
SERVER_CTX = make_server_ctx("controller")
CLIENT_CTX_TO_AH = make_client_ctx("controller")
print(">>> [Controller] 준비 완료\n")

# ==========================================
# [Database] SQLite 초기화 및 조회
# ==========================================
def init_db():
    conn = sqlite3.connect(DB_FILE)
    conn.execute("PRAGMA journal_mode=WAL;")
    c = conn.cursor()

    c.execute('''CREATE TABLE IF NOT EXISTS gateways
                 (device_id TEXT PRIMARY KEY, name TEXT)''')

    c.execute('''CREATE TABLE IF NOT EXISTS services
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  service_id TEXT UNIQUE,
                  gateway_id TEXT,
                  name TEXT,
                  type TEXT,
                  target_ip TEXT,
                  target_port INTEGER,
                  FOREIGN KEY(gateway_id) REFERENCES gateways(device_id))''')

    c.execute('''CREATE TABLE IF NOT EXISTS policies
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  user_cn TEXT,
                  service_id TEXT,
                  FOREIGN KEY(service_id) REFERENCES services(service_id))''')

    conn.commit()
    conn.close()
    print("[DB] 데이터베이스 초기화 및 테이블 로드 완료.")

def get_allowed_services(user_cn):
    """
    특정 사용자(user_cn)에게 허용된 서비스 목록을 조회하고,
    해당 서비스가 속한 Gateway가 현재 'Active' 상태인지 확인하여 반환
    """
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    query = '''
        SELECT s.service_id, s.name, s.type, s.target_ip, s.target_port, s.gateway_id
        FROM policies p
        JOIN services s ON p.service_id = s.service_id
        WHERE p.user_cn = ?
    '''
    c.execute(query, (user_cn,))
    rows = c.fetchall()
    conn.close()

    result_list = []
    for r in rows:
        gw_id = r['gateway_id']

        # 해당 서비스의 Gateway가 현재 접속 중(Active)인지 확인
        if gw_id not in active_gateways:
            continue

        gw_info = active_gateways[gw_id]

        # ★ 핵심 변경:
        # - IH에게 내려주는 "address/port"는 데이터 플레인(AH data_ip:data_port)이어야 함.
        # - 동시에 IH가 9200/9300을 구분할 수 있도록 target_port도 내려줌.
        svc_obj = {
            "id": r['service_id'],          # 64-char hex (DB값)
            "name": r['name'],
            "type": r['type'],

            # 데이터 플레인 주소/포트(=IH가 fwknop + mTLS로 붙을 터널 엔드포인트)
            "address": gw_info['data_ip'],
            "port": gw_info['data_port'],

            # ★ 추가: IH가 원래 목적지(9200/9300) 기준으로 service_id 선택할 수 있게
            "target_port": int(r['target_port']),
        }

        # (옵션) 내부 디버깅/운영 편의. IH가 모르는 필드는 무시해도 됨.
        svc_obj["_gateway_id"] = gw_id

        result_list.append(svc_obj)

    return result_list

# ==========================================
# [기능] 유틸리티
# ==========================================
def recv_until_newline(sock):
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

def get_fwknop_keys():
    try:
        output = subprocess.check_output(["fwknop", "--key-gen"], stderr=subprocess.STDOUT)
        out_str = output.decode("utf-8")
        enc, hmac = None, None
        for line in out_str.splitlines():
            if line.startswith("KEY_BASE64:"):
                enc = line.split(":", 1)[1].strip()
            elif line.startswith("HMAC_KEY_BASE64:"):
                hmac = line.split(":", 1)[1].strip()
        if enc and hmac:
            return enc, hmac
        raise Exception("Key Parse Error")
    except:
        return "def_enc", "def_hmac"

def update_local_fwknoprc(target_ip, target_port, enc, hmac):
    """
    Controller가 AH(auth_port)로 접속하기 위해, fwknop의 stanza를 로컬 ~/.fwknoprc에 추가한다.
    """
    rc_file = os.path.expanduser("~/.fwknoprc")
    stanza = (
        f"\n[{target_ip}]\n"
        f"ALLOW_IP 0.0.0.0\n"
        f"ACCESS tcp/{target_port}\n"
        f"SPA_SERVER {target_ip}\n"
        f"KEY_BASE64 {enc}\n"
        f"HMAC_KEY_BASE64 {hmac}\n"
        f"USE_HMAC Y\n"
    )
    try:
        with open(rc_file, "a") as f:
            f.write(stanza)
        os.chmod(rc_file, 0o600)
    except Exception as e:
        print(f"[Warning] .fwknoprc 업데이트 실패: {e}")

def send_auth_to_ah(gw_info, auth_info):
    """
    AH에게 사용자(IH) 접속 승인 정보 전송 (컨트롤 플레인: mgmt_ip:auth_port)
    """
    ip = gw_info['mgmt_ip']
    port = gw_info['auth_port']
    try:
        print(f"[Controller] AH({ip}:{port})에게 키 배포 시도...")

        # Controller 로컬 ~/.fwknoprc stanza 키로 SPA 전송
        os.system(f"fwknop -A tcp/{port} --fw-timeout 60 -n {ip}")
        time.sleep(1.5)

        raw = socket.create_connection((ip, port), timeout=5)
        sock = CLIENT_CTX_TO_AH.wrap_socket(raw, server_hostname="sdp-ah")
        sock.sendall(bytes([0x05]) + json.dumps(auth_info).encode('utf-8') + b'\n')
        sock.close()

        print("[Controller] AH에게 키 배포 성공.")
        return True
    except Exception as e:
        print(f"[Controller] AH 전송 실패: {e}")
        return False

def get_services_for_gateway(device_id):
    """
    특정 AH(device_id)가 제공하는 서비스 목록을 DB에서 조회하여,
    AH가 service_id로 target_port(9200/9300)를 라우팅할 수 있게 내려준다.
    """
    con_db = sqlite3.connect(DB_FILE)
    con_db.row_factory = sqlite3.Row
    cur = con_db.cursor()
    cur.execute(
        "SELECT service_id, target_ip, target_port FROM services WHERE gateway_id=?",
        (device_id,)
    )
    rows = cur.fetchall()
    con_db.close()

    services = []
    for r in rows:
        services.append({
            "service_id": r["service_id"],       # 64-hex string
            "target_ip": r["target_ip"],         # 보통 127.0.0.1 권장
            "target_port": int(r["target_port"]) # 9200/9300
        })
    return services

# ==========================================
# [Handler] IH (사용자)
# ==========================================
def handle_ih(conn, addr):
    print(f"[Controller-IH] IH 접속: {addr}")
    try:
        if not conn.recv(1):
            return  # Login Request (0x00)

        # [인증] 현재는 테스트를 위해 'client'로 고정
        user_cn = "client"

        sess_id = os.urandom(32).hex()
        enc, hmac = get_fwknop_keys()

        # 1) Login Response
        resp = {
            "session_id": sess_id,
            "credentials": {"spa_encryption_key": enc, "spa_hmac_key": hmac}
        }
        conn.sendall(struct.pack("!BH", 0x01, 200) + json.dumps(resp).encode('utf-8') + b'\n')

        # Keep-Alive Handshake
        if conn.recv(1):
            conn.sendall(bytes([0x03]))

        # 2) RBAC: 이 사용자에게 허용된 서비스 조회 (DB)
        allowed_services = get_allowed_services(user_cn)
        if not allowed_services:
            print(f"[Controller-IH] 사용자({user_cn})에게 할당된 활성 서비스가 없습니다.")

        # 3) 관련 AH들에게 키 배포 (컨트롤 플레인으로)
        #    기존의 ip/port 매칭 대신, svc_obj['_gateway_id']로 바로 선정(정확도/성능 개선)
        target_gateways = set()
        for svc in allowed_services:
            gw_id = svc.get("_gateway_id")
            if gw_id and gw_id in active_gateways:
                target_gateways.add(gw_id)

        auth_info = {
            "IH Authenticators": {
                "IH": f"IH_{addr[0]}",
                "credentials": {"spa_encryption_key": enc, "spa_hmac_key": hmac}
            }
        }

        for gw_id in target_gateways:
            gw_info = active_gateways[gw_id]
            send_auth_to_ah(gw_info, auth_info)

        # 4) 서비스 목록 전송 (0x06)  ─ IH는 여기서 받은 address/port(=data_ip:data_port)로 터널을 연다.
        payload = json.dumps({"services": allowed_services}).encode('utf-8')
        conn.sendall(bytes([0x06]) + payload + b'\n')
        print(f"[Controller-IH] 서비스 목록({len(allowed_services)}개) 전송 완료")

        # keepalive / logout
        while True:
            cmd = conn.recv(1)
            if not cmd or cmd[0] == 0x07:
                break
            if cmd[0] == 0x03:
                conn.sendall(bytes([0x03]))

    except Exception as e:
        print(f"[IH-Error] {e}")
    finally:
        conn.close()

# ==========================================
# [Handler] AH (게이트웨이)
# ==========================================
def handle_ah(conn, addr):
    print(f"[Controller-AH] AH 접속 시도: {addr}")
    sess = None
    device_id = None
    try:
        if not conn.recv(1):
            return  # Login
        req_bytes = recv_until_newline(conn)
        if not req_bytes:
            return
        req = json.loads(req_bytes)

        device_id = req.get('device_id')

        # DB 검증: 등록된 Gateway인지 확인
        con_db = sqlite3.connect(DB_FILE)
        cursor = con_db.cursor()
        cursor.execute("SELECT name FROM gateways WHERE device_id=?", (device_id,))
        row = cursor.fetchone()
        con_db.close()

        if not row:
            print(f"[Controller-AH] 미등록 장비 접속 거부: {device_id}")
            return

        print(f"[Controller-AH] '{row[0]}'({device_id}) 로그인 성공")

        sess = os.urandom(16).hex()

        # ★ 핵심 변경:
        # - addr[0]는 AH가 Controller(컨트롤 플레인)로 접속한 소스IP = mgmt_ip로 취급
        # - data_ip는 AH가 요청(JSON)으로 명시해야 data plane 분리 가능
        #   (없으면 하위호환으로 addr[0] fallback)
        mgmt_ip = addr[0]
        data_ip = req.get("data_ip", addr[0])  # 권장: 192.168.100.250 같은 데이터 NIC IP

        active_gateways[device_id] = {
            "mgmt_ip": mgmt_ip,
            "data_ip": data_ip,
            "auth_port": req['auth_port'],
            "data_port": req['data_port'],
            "session": sess
        }
        print(f"[Controller-AH] 활성 목록 등록됨: {device_id} -> {active_gateways[device_id]}")

        # Controller -> AH(auth_port) 접속용 키 준비
        c_enc, c_hmac = get_fwknop_keys()

        # Controller가 AH 접속 시 사용할 키를 로컬 설정에 저장 (컨트롤 플레인 mgmt_ip:auth_port)
        update_local_fwknoprc(mgmt_ip, req['auth_port'], c_enc, c_hmac)

        # 0x01 Login Response
        resp = {
            "session_id": sess,
            "controller_auth_keys": {"enc": c_enc, "hmac": c_hmac}
        }
        conn.sendall(struct.pack("!BH", 0x01, 200) + json.dumps(resp).encode('utf-8') + b'\n')

        # ★ 변경: 0x04에 "이 AH가 제공하는 서비스 목록" 전달(=AH가 service_id로 9200/9300 분기 가능)
        svc_list = get_services_for_gateway(device_id)
        conn.sendall(bytes([0x04]) + json.dumps({"services": svc_list}).encode('utf-8') + b'\n')

        while True:
            cmd = conn.recv(1)
            if not cmd:
                break

            if cmd[0] == 0x02:  # 로그아웃 요청 확인
                print("[Controller-AH] 로그아웃 요청(0x02) 수신. 종료.")
                break

            # Keep-Alive Ack
            conn.sendall(bytes([0x03]))

    except Exception as e:
        print(f"[AH-Error] {e}")
    finally:
        if device_id and device_id in active_gateways:
            del active_gateways[device_id]
            print(f"[Controller-AH] {device_id} 접속 종료 및 목록 제거")
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
            threading.Thread(target=handler, args=(t, a), daemon=True).start()
        except:
            pass

if __name__ == '__main__':
    init_db()
    threading.Thread(target=serve, args=(IH_PORT, handle_ih), daemon=True).start()
    threading.Thread(target=serve, args=(AH_PORT, handle_ah), daemon=True).start()
    print("[Controller] 서버 가동 중 (DB Mode)...")
    while True:
        time.sleep(1)
