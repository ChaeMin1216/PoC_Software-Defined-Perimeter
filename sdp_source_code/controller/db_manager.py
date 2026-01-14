#!/usr/bin/env python3
import sqlite3
import hashlib
import sys
import os

# Controller와 같은 DB 파일을 바라봐야 합니다.
DB_FILE = "sdp_controller.db"

def get_conn():
    return sqlite3.connect(DB_FILE)

def add_gateway():
    print("\n=== [1. Gateway 등록] ===")
    dev_id = input("Device ID (예: ah01): ").strip()
    name = input("별칭 (예: Factory Main GW): ").strip()
    
    try:
        conn = get_conn()
        conn.execute("INSERT INTO gateways (device_id, name) VALUES (?, ?)", (dev_id, name))
        conn.commit()
        print(f"✅ Gateway '{dev_id}' 등록 완료.")
    except Exception as e:
        print(f"❌ 오류: {e}")
    finally: conn.close()

def add_service():
    print("\n=== [2. Service 등록] ===")
    gw_id = input("연결될 Gateway ID (예: ah01): ").strip()
    name = input("서비스 이름 (예: PLC Unit 3): ").strip()
    ip = input("실제 목적지 IP (예: 192.168.0.100): ").strip()
    port = input("실제 목적지 Port (예: 502): ").strip()
    
    # ID 자동 생성 (SHA-256)
    svc_id = hashlib.sha256(f"{gw_id}_{name}_{ip}_{port}".encode()).hexdigest()
    
    try:
        conn = get_conn()
        # Gateway 존재 여부 확인
        cur = conn.cursor()
        cur.execute("SELECT 1 FROM gateways WHERE device_id=?", (gw_id,))
        if not cur.fetchone():
            print(f"❌ 오류: Gateway '{gw_id}'가 존재하지 않습니다.")
            return

        conn.execute('''INSERT INTO services 
                        (service_id, gateway_id, name, type, target_ip, target_port) 
                        VALUES (?, ?, ?, ?, ?, ?)''', 
                        (svc_id, gw_id, name, "TCP", ip, int(port)))
        conn.commit()
        print(f"✅ 서비스 등록 완료.")
        print(f"   -> Service ID (복사해서 쓰세요): {svc_id}")
    except Exception as e:
        print(f"❌ 오류: {e}")
    finally: conn.close()

def add_policy():
    print("\n=== [3. 정책(Policy) 등록] ===")
    user = input("사용자 CN (예: client): ").strip()
    svc_id = input("허용할 Service ID (64글자 Hex): ").strip()
    
    try:
        conn = get_conn()
        conn.execute("INSERT INTO policies (user_cn, service_id) VALUES (?, ?)", (user, svc_id))
        conn.commit()
        print(f"✅ 정책 추가 완료: {user} -> 서비스 접근 허용")
    except Exception as e:
        print(f"❌ 오류: {e}")
    finally: conn.close()

def list_all():
    conn = get_conn()
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    
    print("\n--- [ Gateways ] ---")
    for r in cur.execute("SELECT * FROM gateways"):
        print(f" - [{r['device_id']}] {r['name']}")
        
    print("\n--- [ Services ] ---")
    for r in cur.execute("SELECT * FROM services"):
        print(f" - [{r['name']}] GW:{r['gateway_id']} Target:{r['target_ip']}:{r['target_port']}")
        print(f"   ID: {r['service_id']}")
        
    print("\n--- [ Policies (Who can access What) ] ---")
    query = '''SELECT p.user_cn, s.name, s.gateway_id 
               FROM policies p JOIN services s ON p.service_id = s.service_id'''
    for r in cur.execute(query):
        print(f" - User '{r['user_cn']}' can access '{r['name']}' (via {r['gateway_id']})")
    
    conn.close()

def main():
    while True:
        print("\n=== SDP Admin Manager ===")
        print("1. Gateway 추가")
        print("2. Service 추가")
        print("3. Policy(권한) 추가")
        print("4. 전체 목록 조회")
        print("0. 종료")
        
        sel = input("선택 > ")
        if sel == '1': add_gateway()
        elif sel == '2': add_service()
        elif sel == '3': add_policy()
        elif sel == '4': list_all()
        elif sel == '0': break
        else: print("잘못된 입력")

if __name__ == '__main__':
    if not os.path.exists(DB_FILE):
        print("⚠️  DB 파일이 없습니다. controller.py를 한 번 실행해서 DB를 생성해주세요.")
    main()
