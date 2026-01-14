import os
import subprocess
import sys

# 경로 설정
CERTS_DIR = "./certs"
CA_KEY = os.path.join(CERTS_DIR, "root-ca.key")
CA_CERT = os.path.join(CERTS_DIR, "root-ca.pem")

def run_cmd(cmd):
    try:
        subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as e:
        print(f"[CertManager] CMD Error: {cmd}\n{e.output.decode()}")
        sys.exit(1)

def ensure_certs_dir():
    if not os.path.exists(CERTS_DIR):
        os.makedirs(CERTS_DIR)

def ensure_root_ca():
    """
    제조사 Root CA가 없으면 생성 (최초 1회)
    현실에서는 이 과정이 '공장'에서 이루어지고, 파일이 배포된다고 가정.
    """
    ensure_certs_dir()
    if not os.path.exists(CA_KEY) or not os.path.exists(CA_CERT):
        print("[CertManager] 제조사 Root CA가 없습니다. 생성합니다...")
        cmd = (
            f"openssl req -new -x509 -days 3650 -nodes -out {CA_CERT} -keyout {CA_KEY} "
            f"-subj '/CN=Manufacturer-Root-CA' "
            f"-addext 'basicConstraints=critical,CA:TRUE' "
            f"-addext 'keyUsage=critical,keyCertSign,cRLSign'"
        )
        run_cmd(cmd)
        print("[CertManager] Root CA 생성 완료.")

def ensure_device_cert(role):
    """
    내 기기(role)의 인증서가 없으면, 로컬의 Root CA를 이용해 발급
    """
    ensure_certs_dir()
    ensure_root_ca() # CA가 있어야 서명 가능

    key_file = os.path.join(CERTS_DIR, f"{role}-key.pem")
    cert_file = os.path.join(CERTS_DIR, f"{role}-cert.pem")
    csr_file = os.path.join(CERTS_DIR, f"{role}.csr")
    ext_file = os.path.join(CERTS_DIR, f"{role}.ext")

    if os.path.exists(key_file) and os.path.exists(cert_file):
        # 이미 인증서가 있으면 패스
        return

    print(f"[CertManager] '{role}'용 인증서 발급 중 (Local CA 서명)...")

    # 1. CSR 생성
    cmd_csr = (f"openssl req -new -nodes -out {csr_file} -keyout {key_file} "
               f"-subj '/CN=sdp-{role}'")
    run_cmd(cmd_csr)

    # 2. 확장 설정 파일 (IP 검증 끄기용)
    with open(ext_file, "w") as f:
        f.write("basicConstraints=CA:FALSE\n")
        f.write("keyUsage=digitalSignature,keyEncipherment\n")
        f.write("extendedKeyUsage=serverAuth,clientAuth\n")

    # 3. CA 서명
    cmd_sign = (f"openssl x509 -req -in {csr_file} "
                f"-CA {CA_CERT} -CAkey {CA_KEY} -CAcreateserial "
                f"-out {cert_file} -days 3650 "
                f"-extfile {ext_file}")
    run_cmd(cmd_sign)

    # 4. 정리
    if os.path.exists(csr_file): os.remove(csr_file)
    if os.path.exists(ext_file): os.remove(ext_file)
    print(f"[CertManager] '{role}' 인증서 발급 완료.")
