# tls_util.py
from pathlib import Path
import ssl
import os

# cert_manager와 동일하게 ./certs 폴더를 바라봄
BASE_DIR = Path(__file__).resolve().parent
CERT_DIR = BASE_DIR / "certs"
CA_FILE  = CERT_DIR / "root-ca.pem"

def _pair(role: str):
    # 역할 이름(ah, ih, controller)에 맞는 인증서/키 경로 반환
    cert = CERT_DIR / f"{role}-cert.pem"
    key  = CERT_DIR / f"{role}-key.pem"
    if not (cert.exists() and key.exists()):
        raise FileNotFoundError(f"[tls_util] '{role}' 인증서가 {CERT_DIR}에 없습니다. 자동 발급이 필요합니다.")
    return cert, key

def make_server_ctx(role: str) -> ssl.SSLContext:
    """서버용 SSL Context (Controller, AH 등)"""
    cert, key = _pair(role)
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.load_cert_chain(certfile=str(cert), keyfile=str(key))
    
    # 상대방(Client)도 반드시 우리 CA가 발급한 인증서를 가져와야 함
    ctx.load_verify_locations(cafile=str(CA_FILE))
    ctx.verify_mode = ssl.CERT_REQUIRED
    
    # ★ 핵심: 테스트 환경 유연성을 위해 IP 주소 검증 비활성화
    ctx.check_hostname = False  
    return ctx

def make_client_ctx(role: str) -> ssl.SSLContext:
    """클라이언트용 SSL Context (IH, AH 등)"""
    cert, key = _pair(role)
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(CA_FILE))
    ctx.load_cert_chain(certfile=str(cert), keyfile=str(key))
    
    # ★ 핵심: 서버의 인증서는 검증하되, IP 주소 일치 여부는 무시
    ctx.check_hostname = False
    return ctx
