import os
import random
import uuid
from datetime import datetime, timedelta
import pandas as pd
import numpy as np

def generate_synthetic_data(num_users=50, num_days=30, output_path="data/raw/security_logs.csv"):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    random.seed(42)
    np.random.seed(42)

    departments = ["Engineering", "Finance", "HR", "Executive", "IT Admin"]
    roles = {
        "Engineering": ["Software Engineer", "DevOps Lead", "QA Specialist"],
        "Finance": ["Financial Analyst", "Accountant", "Finance Manager"],
        "HR": ["HR Specialist", "Recruiter", "HRBP"],
        "Executive": ["VP of Operations", "Chief Chief", "Director"],
        "IT Admin": ["Systems Administrator", "Network Admin", "Security Analyst"]
    }

    countries = ["USA", "USA", "USA", "USA", "Canada", "UK", "Germany"]
    unusual_countries = ["Russia", "North Korea", "Romania", "Brazil", "China"]

    users = []
    user_baselines = {}
    
    # 1. Create Users & Baselines
    for i in range(101, 101 + num_users):
        user_id = f"U{i}"
        dept = random.choice(departments)
        role = random.choice(roles[dept])
        primary_ip = f"10.{random.randint(1,5)}.{random.randint(1,10)}.{random.randint(2,250)}"
        primary_dev = f"DEV_{dept[:3].upper()}_{i}"
        
        start_hour = random.choice([8, 9])
        end_hour = random.choice([17, 18, 19])
        
        dept_resources = {
            "Engineering": ["/code/main_app", "/code/api_service", "/jira/tickets", "/docs/architecture.pdf"],
            "Finance": ["/finance/q3_report.xlsx", "/finance/invoices/", "/finance/budgets_2026.pdf"],
            "HR": ["/hr/employee_records", "/hr/benefits.pdf", "/hr/performance_reviews/"],
            "Executive": ["/exec/board_deck.pptx", "/exec/strategy_2027.pdf", "/finance/summary.xlsx"],
            "IT Admin": ["/admin/syslogs", "/admin/backups", "/config/router_cfg", "/code/main_app"]
        }

        users.append({
            "user_id": user_id,
            "department": dept,
            "role": role,
            "primary_ip": primary_ip,
            "primary_dev": primary_dev,
            "start_hour": start_hour,
            "end_hour": end_hour,
            "resources": dept_resources[dept]
        })
        
        user_baselines[user_id] = {
            "dept": dept,
            "role": role,
            "ips": [primary_ip, f"10.{random.randint(1,5)}.{random.randint(1,10)}.{random.randint(2,250)}"],
            "devices": [primary_dev],
            "start_hour": start_hour,
            "end_hour": end_hour,
            "resources": dept_resources[dept],
            "avg_bytes": random.randint(1_000_000, 15_000_000) # 1 MB - 15 MB
        }

    # Generate log events
    events = []
    event_id_counter = 10000
    start_date = datetime(2026, 8, 1, 8, 0, 0)

    # 2. Normal Activity Generation across Days
    for day in range(num_days):
        current_date = start_date + timedelta(days=day)
        is_weekend = current_date.weekday() >= 5

        for u in users:
            uid = u["user_id"]
            b = user_baselines[uid]

            # Reduced probability on weekends
            if is_weekend and random.random() > 0.15:
                continue

            # Normal workday sessions (1 to 3 sessions per day)
            num_sessions = random.randint(1, 3)
            for s in range(num_sessions):
                session_id = f"S_{uid}_{day}_{s}_{uuid.uuid4().hex[:6]}"
                
                # Session start time within normal hours
                session_hour = random.randint(b["start_hour"], b["end_hour"] - 1)
                session_minute = random.randint(0, 59)
                session_time = current_date.replace(hour=session_hour, minute=session_minute, second=random.randint(0,59))
                
                source_ip = random.choice(b["ips"])
                device_id = random.choice(b["devices"])
                country = random.choice(countries)

                # Event 1: Successful Login
                event_id_counter += 1
                events.append({
                    "event_id": str(event_id_counter),
                    "timestamp": session_time.strftime("%Y-%m-%d %H:%M:%S"),
                    "user_id": uid,
                    "source_ip": source_ip,
                    "country": country,
                    "device_id": device_id,
                    "event_type": "LOGIN",
                    "resource": "-",
                    "action": "LOGIN_SUCCESS",
                    "status": "SUCCESS",
                    "session_id": session_id,
                    "bytes_transferred": 0,
                    "duration": random.randint(1, 3)
                })

                # Normal file & system activity in session
                num_file_events = random.randint(2, 6)
                for _ in range(num_file_events):
                    session_time += timedelta(minutes=random.randint(2, 25))
                    event_id_counter += 1
                    resource = random.choice(b["resources"])
                    action = random.choice(["FILE_READ", "FILE_WRITE", "FILE_READ"])
                    bytes_tx = random.randint(50_000, int(b["avg_bytes"] / 4))

                    events.append({
                        "event_id": str(event_id_counter),
                        "timestamp": session_time.strftime("%Y-%m-%d %H:%M:%S"),
                        "user_id": uid,
                        "source_ip": source_ip,
                        "country": country,
                        "device_id": device_id,
                        "event_type": "FILE",
                        "resource": resource,
                        "action": action,
                        "status": "SUCCESS",
                        "session_id": session_id,
                        "bytes_transferred": bytes_tx,
                        "duration": random.randint(2, 30)
                    })

                # Periodic network connection / password change in normal sessions
                if random.random() < 0.10:
                    session_time += timedelta(minutes=1)
                    event_id_counter += 1
                    events.append({
                        "event_id": str(event_id_counter),
                        "timestamp": session_time.strftime("%Y-%m-%d %H:%M:%S"),
                        "user_id": uid,
                        "source_ip": source_ip,
                        "country": country,
                        "device_id": device_id,
                        "event_type": "AUTHENTICATION",
                        "resource": "-",
                        "action": "PASSWORD_CHANGE",
                        "status": "SUCCESS",
                        "session_id": session_id,
                        "bytes_transferred": 0,
                        "duration": 2
                    })
                elif random.random() < 0.20:
                    session_time += timedelta(minutes=1)
                    event_id_counter += 1
                    events.append({
                        "event_id": str(event_id_counter),
                        "timestamp": session_time.strftime("%Y-%m-%d %H:%M:%S"),
                        "user_id": uid,
                        "source_ip": source_ip,
                        "country": country,
                        "device_id": device_id,
                        "event_type": "NETWORK",
                        "resource": "10.0.0.1:443",
                        "action": "CONNECTION",
                        "status": "SUCCESS",
                        "session_id": session_id,
                        "bytes_transferred": random.randint(1000, 50000),
                        "duration": random.randint(5, 60)
                    })

                # Event Logout
                session_time += timedelta(minutes=random.randint(5, 30))
                event_id_counter += 1
                events.append({
                    "event_id": str(event_id_counter),
                    "timestamp": session_time.strftime("%Y-%m-%d %H:%M:%S"),
                    "user_id": uid,
                    "source_ip": source_ip,
                    "country": country,
                    "device_id": device_id,
                    "event_type": "AUTHENTICATION",
                    "resource": "-",
                    "action": "LOGOUT",
                    "status": "SUCCESS",
                    "session_id": session_id,
                    "bytes_transferred": 0,
                    "duration": 0
                })

    # 3. Inject Realistic Multi-Step Attack Scenarios
    print("[+] Injecting realistic threat & attack scenarios...")

    # Scenario 1: Insider Threat Data Exfiltration (User U103 - Finance)
    # Day 26, 02:15 AM (After hours, alien IP, new device, sensitive resource, huge transfer)
    att_time_1 = start_date + timedelta(days=25, hours=2, minutes=15)
    att_session_1 = f"S_ATTACK_U103_{uuid.uuid4().hex[:6]}"
    alien_ip_1 = "185.220.101.4"
    alien_dev_1 = "DEV_UNKNOWN_991"
    
    # Login success from unseen IP/Device
    event_id_counter += 1
    events.append({
        "event_id": str(event_id_counter),
        "timestamp": att_time_1.strftime("%Y-%m-%d %H:%M:%S"),
        "user_id": "U103",
        "source_ip": alien_ip_1,
        "country": "Russia",
        "device_id": alien_dev_1,
        "event_type": "LOGIN",
        "resource": "-",
        "action": "LOGIN_SUCCESS",
        "status": "SUCCESS",
        "session_id": att_session_1,
        "bytes_transferred": 0,
        "duration": 5
    })
    # Sensitive file read
    att_time_1 += timedelta(minutes=2)
    event_id_counter += 1
    events.append({
        "event_id": str(event_id_counter),
        "timestamp": att_time_1.strftime("%Y-%m-%d %H:%M:%S"),
        "user_id": "U103",
        "source_ip": alien_ip_1,
        "country": "Russia",
        "device_id": alien_dev_1,
        "event_type": "FILE",
        "resource": "/hr/payroll_all_employees.xlsx",
        "action": "FILE_READ",
        "status": "SUCCESS",
        "session_id": att_session_1,
        "bytes_transferred": 1_200_000,
        "duration": 12
    })
    # Massive download exfiltration (520 MB)
    att_time_1 += timedelta(minutes=3)
    event_id_counter += 1
    events.append({
        "event_id": str(event_id_counter),
        "timestamp": att_time_1.strftime("%Y-%m-%d %H:%M:%S"),
        "user_id": "U103",
        "source_ip": alien_ip_1,
        "country": "Russia",
        "device_id": alien_dev_1,
        "event_type": "FILE",
        "resource": "/hr/confidential_payroll_backup.zip",
        "action": "FILE_DOWNLOAD",
        "status": "SUCCESS",
        "session_id": att_session_1,
        "bytes_transferred": 520_000_000,
        "duration": 340
    })

    # Scenario 2: Credential Stuffing & Privilege Escalation (User U112 - HR)
    # Day 28, 23:40 PM (Failed logins burst -> success -> admin escalation -> exfiltration)
    att_time_2 = start_date + timedelta(days=27, hours=23, minutes=40)
    att_session_2 = f"S_ATTACK_U112_{uuid.uuid4().hex[:6]}"
    alien_ip_2 = "194.26.29.11"
    alien_dev_2 = "DEV_COMPROMISED_88"

    for fail_idx in range(7):
        att_time_2 += timedelta(seconds=25)
        event_id_counter += 1
        events.append({
            "event_id": str(event_id_counter),
            "timestamp": att_time_2.strftime("%Y-%m-%d %H:%M:%S"),
            "user_id": "U112",
            "source_ip": alien_ip_2,
            "country": "Romania",
            "device_id": alien_dev_2,
            "event_type": "LOGIN",
            "resource": "-",
            "action": "LOGIN_FAILURE",
            "status": "FAIL",
            "session_id": att_session_2,
            "bytes_transferred": 0,
            "duration": 1
        })
    
    # Successful login after burst
    att_time_2 += timedelta(seconds=30)
    event_id_counter += 1
    events.append({
        "event_id": str(event_id_counter),
        "timestamp": att_time_2.strftime("%Y-%m-%d %H:%M:%S"),
        "user_id": "U112",
        "source_ip": alien_ip_2,
        "country": "Romania",
        "device_id": alien_dev_2,
        "event_type": "LOGIN",
        "resource": "-",
        "action": "LOGIN_SUCCESS",
        "status": "SUCCESS",
        "session_id": att_session_2,
        "bytes_transferred": 0,
        "duration": 2
    })
    # Privilege Escalation
    att_time_2 += timedelta(minutes=2)
    event_id_counter += 1
    events.append({
        "event_id": str(event_id_counter),
        "timestamp": att_time_2.strftime("%Y-%m-%d %H:%M:%S"),
        "user_id": "U112",
        "source_ip": alien_ip_2,
        "country": "Romania",
        "device_id": alien_dev_2,
        "event_type": "PRIVILEGE",
        "resource": "/admin/sudoers",
        "action": "PRIVILEGE_ESCALATION",
        "status": "SUCCESS",
        "session_id": att_session_2,
        "bytes_transferred": 0,
        "duration": 10
    })
    # Executive Deck Exfiltration (450 MB)
    att_time_2 += timedelta(minutes=4)
    event_id_counter += 1
    events.append({
        "event_id": str(event_id_counter),
        "timestamp": att_time_2.strftime("%Y-%m-%d %H:%M:%S"),
        "user_id": "U112",
        "source_ip": alien_ip_2,
        "country": "Romania",
        "device_id": alien_dev_2,
        "event_type": "FILE",
        "resource": "/exec/board_deck_confidential.pptx",
        "action": "FILE_DOWNLOAD",
        "status": "SUCCESS",
        "session_id": att_session_2,
        "bytes_transferred": 450_000_000,
        "duration": 210
    })

    # Scenario 3: Lateral Movement & Database Recon (User U125 - Engineering)
    # Day 27, 03:10 AM
    att_time_3 = start_date + timedelta(days=26, hours=3, minutes=10)
    att_session_3 = f"S_ATTACK_U125_{uuid.uuid4().hex[:6]}"
    alien_ip_3 = "10.99.1.50"
    alien_dev_3 = "DEV_ENG_125"

    event_id_counter += 1
    events.append({
        "event_id": str(event_id_counter),
        "timestamp": att_time_3.strftime("%Y-%m-%d %H:%M:%S"),
        "user_id": "U125",
        "source_ip": alien_ip_3,
        "country": "USA",
        "device_id": alien_dev_3,
        "event_type": "NETWORK",
        "resource": "10.0.0.1:3306",
        "action": "PORT_ACCESS",
        "status": "SUCCESS",
        "session_id": att_session_3,
        "bytes_transferred": 0,
        "duration": 5
    })
    att_time_3 += timedelta(minutes=3)
    event_id_counter += 1
    events.append({
        "event_id": str(event_id_counter),
        "timestamp": att_time_3.strftime("%Y-%m-%d %H:%M:%S"),
        "user_id": "U125",
        "source_ip": alien_ip_3,
        "country": "USA",
        "device_id": alien_dev_3,
        "event_type": "NETWORK",
        "resource": "/db/prod/customer_master_database.sql",
        "action": "REMOTE_LOGIN",
        "status": "SUCCESS",
        "session_id": att_session_3,
        "bytes_transferred": 0,
        "duration": 15
    })
    att_time_3 += timedelta(minutes=5)
    event_id_counter += 1
    events.append({
        "event_id": str(event_id_counter),
        "timestamp": att_time_3.strftime("%Y-%m-%d %H:%M:%S"),
        "user_id": "U125",
        "source_ip": alien_ip_3,
        "country": "USA",
        "device_id": alien_dev_3,
        "event_type": "FILE",
        "resource": "/db/prod/customer_master_database.sql",
        "action": "FILE_DOWNLOAD",
        "status": "SUCCESS",
        "session_id": att_session_3,
        "bytes_transferred": 850_000_000,
        "duration": 600
    })

    # Scenario 4: Removable Media & Mass Deletion (User U145 - IT Admin)
    # Day 29, 21:00 PM
    att_time_4 = start_date + timedelta(days=28, hours=21, minutes=0)
    att_session_4 = f"S_ATTACK_U145_{uuid.uuid4().hex[:6]}"
    ip_4 = "10.4.1.15"
    dev_4 = "DEV_ADM_145"

    event_id_counter += 1
    events.append({
        "event_id": str(event_id_counter),
        "timestamp": att_time_4.strftime("%Y-%m-%d %H:%M:%S"),
        "user_id": "U145",
        "source_ip": ip_4,
        "country": "USA",
        "device_id": dev_4,
        "event_type": "DEVICE",
        "resource": "USB_MASS_STORAGE_V2",
        "action": "USB_CONNECT",
        "status": "SUCCESS",
        "session_id": att_session_4,
        "bytes_transferred": 0,
        "duration": 1
    })
    
    # Mass file deletions
    for del_i in range(18):
        att_time_4 += timedelta(seconds=15)
        event_id_counter += 1
        events.append({
            "event_id": str(event_id_counter),
            "timestamp": att_time_4.strftime("%Y-%m-%d %H:%M:%S"),
            "user_id": "U145",
            "source_ip": ip_4,
            "country": "USA",
            "device_id": dev_4,
            "event_type": "FILE",
            "resource": f"/admin/backups/backup_day_{del_i}.tar.gz",
            "action": "FILE_DELETE",
            "status": "SUCCESS",
            "session_id": att_session_4,
            "bytes_transferred": 0,
            "duration": 2
        })

    att_time_4 += timedelta(seconds=30)
    event_id_counter += 1
    events.append({
        "event_id": str(event_id_counter),
        "timestamp": att_time_4.strftime("%Y-%m-%d %H:%M:%S"),
        "user_id": "U145",
        "source_ip": ip_4,
        "country": "USA",
        "device_id": dev_4,
        "event_type": "PRIVILEGE",
        "resource": "/admin/root_console",
        "action": "ADMIN_ACCESS",
        "status": "SUCCESS",
        "session_id": att_session_4,
        "bytes_transferred": 0,
        "duration": 5
    })

    att_time_4 += timedelta(seconds=20)
    event_id_counter += 1
    events.append({
        "event_id": str(event_id_counter),
        "timestamp": att_time_4.strftime("%Y-%m-%d %H:%M:%S"),
        "user_id": "U145",
        "source_ip": ip_4,
        "country": "USA",
        "device_id": dev_4,
        "event_type": "DEVICE",
        "resource": "USB_MASS_STORAGE_V2",
        "action": "USB_DISCONNECT",
        "status": "SUCCESS",
        "session_id": att_session_4,
        "bytes_transferred": 0,
        "duration": 1
    })

    # Convert to pandas DataFrame and sort by timestamp
    df = pd.DataFrame(events)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df = df.sort_values(by="timestamp").reset_index(drop=True)
    df["timestamp"] = df["timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S")

    df.to_csv(output_path, index=False)
    print(f"[+] Successfully generated {len(df)} realistic enterprise security log events -> {output_path}")

    # Export User Metadata
    users_df = pd.DataFrame(users)[["user_id", "department", "role"]]
    users_df["created_at"] = start_date.strftime("%Y-%m-%d %H:%M:%S")
    
    devices = []
    for u in users:
        devices.append({
            "device_id": u["primary_dev"],
            "user_id": u["user_id"],
            "device_type": "Corporate Laptop",
            "os_info": "Windows 11 Enterprise"
        })
    devices_df = pd.DataFrame(devices)

    return df, users_df, devices_df

if __name__ == "__main__":
    generate_synthetic_data()
