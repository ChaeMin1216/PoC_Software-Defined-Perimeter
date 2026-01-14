#!/usr/bin/env python3
import socket
import json
import subprocess
import os
import sys
import ssl
import atexit
import signal
from tls_util import make_server_ctx

# ==========================================
# [관리자 설정]
# ==========================================
PROVISION_PORT = 30000
ACCESS_CONF = "/etc/fwknop/access.conf"
OPEN_PORTS_LIST = "tcp/4433,tcp/4444,tcp/8888"
RESET_SCRIPT = "./iptables_sdp_setup.sh"

def check_root():
    if os.geteuid() != 0:
        print("[Error] iptables 제어를 위해 sudo 권한으로 실행해주세요.")
        sys.exit(1)

def setup_firewall_allow():
    print(f"[Admin] 프로비저닝 포트({PROVISION_PORT}) 개방 중...")
    cmd = f"iptables -I INPUT 1 -p tcp --dport {PROVISION_PORT} -j ACCEPT"
    try:
        subprocess.run(cmd.split(), check=True)
        print(f"[Admin] Port {PROVISION_PORT} Opened.")
    except subprocess.CalledProcessError as e:
        print(f"[Error] 방화벽 설정 실패: {e}")
        sys.exit(1)

def restore_security_state():
    print("\n[Admin] 보안 상태 원상복구(Reset) 진행 중...")
    if os.path.exists(RESET_SCRIPT):
        try:
            subprocess.run(RESET_SCRIPT, shell=True, check=True)
            print(f"[Admin] '{RESET_SCRIPT}' 실행 완료.")
        except Exception as e:
            print(f"[Error] 초기화 스크립트 실행 실패: {e}")
    
    print("[Admin] fwknopd 서비스 재시작 중...")
    try:
        subprocess.run(["fwknopd", "-R"], check=False)
        print("[Admin] fwknopd 리로드 완료.")
    except: pass
    print("[Admin] 종료 완료.")

def get_fwknop_keys():
    """
    fwknop --key-gen 실행 및 파싱
    """
    try:
        output = subprocess.check_output(["fwknop", "--key-gen"], stderr=subprocess.STDOUT)
        out_str = output.decode("utf-8")
        
        enc_key = None
        hmac_key = None
        
        for line in out_str.splitlines():
            line = line.strip() # 공백 제거
            
            # ★ 수정된 부분: startswith를 사용하여 정확히 구분
            if line.startswith("KEY_BASE64:"):
                parts = line.split(":", 1)
                if len(parts) > 1:
                    enc_key = parts[1].strip()
            elif line.startswith("HMAC_KEY_BASE64:"):
                parts = line.split(":", 1)
                if len(parts) > 1:
                    hmac_key = parts[1].strip()
        
        if not enc_key or not hmac_key:
            print("\n[DEBUG] 파싱 실패. 원본 출력:")
            print(out_str)
            raise Exception("키 값을 파싱할 수 없습니다.")
            
        return enc_key, hmac_key

    except subprocess.CalledProcessError as e:
        print(f"[Error] fwknop 명령어 실행 오류: {e.output.decode()}")
        sys.exit(1)
    except Exception as e:
        print(f"[Error] 키 생성 로직 실패: {e}")
        sys.exit(1)

def update_access_conf(enc, hmac):
    stanza = f"""
# --- PROVISIONED CLIENT START ---
SOURCE              ANY
OPEN_PORTS          {OPEN_PORTS_LIST}
KEY_BASE64          {enc}
HMAC_KEY_BASE64     {hmac}
# --- PROVISIONED CLIENT END ---
"""
    try:
        with open(ACCESS_CONF, "a") as f:
            f.write(stanza)
        print("[Admin] access.conf 업데이트 완료.")
    except Exception as e:
        print(f"[Error] 설정 파일 쓰기 실패: {e}")

def handle_client(conn, addr):
    print(f"[Admin] 클라이언트 접속: {addr}")
    try:
        enc, hmac = get_fwknop_keys()
        print(f"[Admin] 키 생성 성공 (Enc: {enc[:5]}...)")

        update_access_conf(enc, hmac)

        payload = {"spa_encryption_key": enc, "spa_hmac_key": hmac}
        conn.sendall(json.dumps(payload).encode('utf-8') + b'\n')
        print(f"[Admin] 전송 완료 -> {addr}")
    except Exception as e:
        print(f"[Error] 클라이언트 처리 중 오류: {e}")
    finally:
        conn.close()

def signal_handler(sig, frame):
    sys.exit(0)

def main():
    check_root()
    signal.signal(signal.SIGINT, signal_handler)
    atexit.register(restore_security_state)

    try:
        ctx = make_server_ctx("controller")
    except:
        print("[Error] 인증서 오류. certs 폴더 확인 필요.")
        sys.exit(1)

    setup_firewall_allow()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(('0.0.0.0', PROVISION_PORT))
        s.listen(5)
        print(f"\n=== [관리자 모드] 키 배포 서버 (Port: {PROVISION_PORT}) ===")
        print(">>> AH / IH에서 admin_client.py를 실행하세요.")
        
        while True:
            try:
                conn, addr = s.accept()
                tls_conn = ctx.wrap_socket(conn, server_side=True)
                handle_client(tls_conn, addr)
            except Exception as e:
                print(f"[Warning] 연결 오류: {e}")

if __name__ == '__main__':
    main()
