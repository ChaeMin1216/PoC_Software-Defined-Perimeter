#!/usr/bin/env python3
import socket
import json
import os
import sys
import ssl
import fcntl
import struct
from tls_util import make_client_ctx

# ==========================================
# [설정]
# ==========================================
# ★ 중요: Controller IP는 고정
CONTROLLER_IP = '172.16.255.2' 
PROVISION_PORT = 30000

def get_local_ip(ifname="eth1"):
    """로컬 IP 확인 (ALLOW_IP 설정용)"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return socket.inet_ntoa(fcntl.ioctl(
            s.fileno(), 0x8915, struct.pack('256s', ifname[:15].encode('utf-8'))
        )[20:24])
    except:
        # 인터페이스 못 찾으면 구글 DNS 접속 시도로 IP 확인
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
        except:
            return "0.0.0.0"

def update_fwknoprc(target_ip, enc, hmac):
    """
    [Client Side] ~/.fwknoprc 파일 생성
    튜토리얼에 따라 Stanza 이름, Access 포트, 키 등을 설정
    """
    rc_path = os.path.expanduser("~/.fwknoprc")
    my_ip = get_local_ip()
    
    # Stanza 이름은 대상 IP와 같아야 'fwknop -n IP' 명령이 동작함
    stanza = f"""
[{target_ip}]
ALLOW_IP            {my_ip}
ACCESS              tcp/4433,tcp/4444,tcp/8888
SPA_SERVER          {target_ip}
KEY_BASE64          {enc}
HMAC_KEY_BASE64     {hmac}
USE_HMAC            Y
"""
    try:
        # 기존 파일이 있으면 백업하거나 내용을 추가해야 하지만,
        # 확실한 설정을 위해 여기서는 'w' 모드로 새로 씁니다.
        with open(rc_path, "w") as f:
            f.write(stanza)
        
        # 보안 권한 설정 (필수: fwknop은 권한이 널널하면 거부함)
        os.chmod(rc_path, 0o600)
        print(f"[Client] ~/.fwknoprc 파일 생성 완료.")
        print(f"         Target Stanza: [{target_ip}]")
        
    except Exception as e:
        print(f"[Error] 파일 쓰기 실패: {e}")

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

def main():
    # 실행 인자로 역할 구분 (ah 또는 ih) - 인증서 로드용
    if len(sys.argv) < 2:
        print("사용법: python3 admin_client.py [ah|ih]")
        sys.exit(1)
    
    role = sys.argv[1]
    print(f"=== [관리자 모드] 키 수신 클라이언트 ({role}) ===")
    
    # mTLS 컨텍스트 (제조사 인증서)
    try:
        ctx = make_client_ctx(role)
    except FileNotFoundError:
        print(f"[Error] certs/{role}-cert.pem 이 없습니다. {role}.py를 한번 실행해서 인증서를 만드세요.")
        sys.exit(1)

    try:
        print(f">>> Controller({CONTROLLER_IP}:{PROVISION_PORT}) 접속 시도...")
        raw = socket.create_connection((CONTROLLER_IP, PROVISION_PORT))
        sock = ctx.wrap_socket(raw, server_hostname="sdp-controller")
        
        # 데이터 수신
        data = recv_until_newline(sock)
        if not data:
            print("[Error] 데이터 수신 실패 (연결 끊김)")
            sys.exit(1)
            
        info = json.loads(data)
        print("[Client] 키 정보 수신 완료!")
        print(f" - Enc Key : {info['spa_encryption_key'][:15]}...")
        print(f" - HMAC Key: {info['spa_hmac_key'][:15]}...")
        
        # 설정 파일 업데이트
        update_fwknoprc(CONTROLLER_IP, info['spa_encryption_key'], info['spa_hmac_key'])
        
        print("\n[Success] 설정이 완료되었습니다.")
        print(f"이제 'fwknop -n {CONTROLLER_IP} ...' 명령이 동작합니다.")
        
    except Exception as e:
        print(f"[Error] 접속/처리 오류: {e}")
    finally:
        if 'sock' in locals(): sock.close()

if __name__ == '__main__':
    main()
