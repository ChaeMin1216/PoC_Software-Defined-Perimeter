#!/bin/bash

echo "[+] 기존 iptables 규칙 초기화..."
sudo iptables -F
sudo iptables -X
sudo iptables -Z

echo "[+] 기본 정책 설정 (INPUT: DROP, FORWARD: DROP, OUTPUT: ACCEPT)"
sudo iptables -P INPUT DROP
sudo iptables -P FORWARD DROP
sudo iptables -P OUTPUT ACCEPT

# =================================================================
# Loopback(로컬호스트) 통신 허용
# 이 부분이 없으면 127.0.0.1로 가는 패킷이 차단되어 Timeout 발생함
# =================================================================
echo "[+] 로컬 루프백(lo) 인터페이스 통신 허용"
sudo iptables -A INPUT -i lo -j ACCEPT
sudo iptables -A OUTPUT -o lo -j ACCEPT

echo "[+] fwknop SPA 패킷 수신 허용 (UDP 62201)"
sudo iptables -A INPUT -p udp --dport 62201 -j ACCEPT

echo "[+] ESTABLISHED, RELATED 연결 허용 (응답 패킷 허용)"
sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

echo "[+] fwknopd 서비스 재시작 중..."
# fwknopd가 iptables 체인을 다시 잡을 수 있도록 재시작
sudo systemctl restart fwknop-server.service
sleep 2

echo "[+] 현재 iptables 규칙 확인:"
sudo iptables -L -n -v --line-numbers
