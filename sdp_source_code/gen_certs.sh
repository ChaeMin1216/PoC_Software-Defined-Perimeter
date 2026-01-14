#!/bin/bash

# 1. 올바른 CA 생성 (핵심: CA:TRUE 및 keyCertSign 포함)
echo "Generating Root CA..."
openssl req -new -x509 -days 3650 -nodes -out ca.crt -keyout ca.key -subj "/CN=SDP-Root-CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"

# 2. 컴포넌트별 인증서 생성 함수 (핵심: IP SAN 포함)
gen_cert() {
    NAME=$1
    IP=$2
    echo "Generating certificate for $NAME ($IP)..."

    # CSR 생성
    openssl req -new -nodes -out $NAME.csr -keyout $NAME.key -subj "/CN=sdp-$NAME"
    
    # CA로 서명 (IP 주소 포함, Server/Client 인증 용도 명시)
    openssl x509 -req -in $NAME.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out $NAME.crt -days 365 \
      -copy_extensions copy \
      -addext "basicConstraints=CA:FALSE" \
      -addext "keyUsage=digitalSignature,keyEncipherment" \
      -addext "extendedKeyUsage=serverAuth,clientAuth" \
      -addext "subjectAltName=IP:$IP,IP:127.0.0.1"
}

# 3. 각 장비 IP에 맞춰 생성 (사용자님 환경의 IP 반영)
gen_cert "controller" "192.168.163.129"
gen_cert "ah" "192.168.163.130"
gen_cert "ih" "192.168.163.131"

# 4. 파일명 변경 (Python 코드의 tls_util.py가 .pem 확장자를 찾으므로 변환)
# ca.crt -> root-ca.pem
cp ca.crt root-ca.pem
# *.crt, *.key -> *-cert.pem, *-key.pem
for role in controller ah ih; do
    cp $role.crt $role-cert.pem
    cp $role.key $role-key.pem
done

# 5. 정리
rm *.csr *.srl *.crt *.key
echo "===== 완료 ====="
echo "생성된 PEM 파일들을 각 장비의 certs/ 폴더로 복사하세요."
