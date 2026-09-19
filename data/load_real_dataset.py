import os
import sys
import argparse
import uuid
import pandas as pd
import numpy as np

# Ensure root directory is on python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

def convert_cert_dataset(cert_dir: str, output_path: str = "data/raw/security_logs.csv"):
    """Converts CMU/CERT Insider Threat Dataset r4.2/r5.2 (logon.csv, file.csv, device.csv) to standard schema."""
    print(f"[+] Processing CERT Insider Threat Dataset from: {cert_dir}")
    events = []

    # 1. Process Logon.csv
    logon_file = os.path.join(cert_dir, "logon.csv")
    if os.path.exists(logon_file):
        print("  -> Parsing logon.csv...")
        df_logon = pd.read_csv(logon_file)
        # Columns: id, date, user, pc, activity
        for idx, row in df_logon.iterrows():
            activity = str(row.get("activity", "Logon"))
            is_login = "Logon" in activity
            events.append({
                "event_id": str(row.get("id", f"EVT_CERT_LOGON_{idx}")),
                "timestamp": str(row.get("date")),
                "user_id": str(row.get("user")),
                "source_ip": f"10.1.{hash(str(row.get('pc'))) % 250 + 1}.{idx % 254 + 1}",
                "country": "USA",
                "device_id": str(row.get("pc")),
                "event_type": "AUTHENTICATION",
                "resource": "-",
                "action": "LOGIN_SUCCESS" if is_login else "LOGOUT",
                "status": "SUCCESS",
                "session_id": f"S_CERT_{row.get('user')}_{str(row.get('date'))[:10]}",
                "bytes_transferred": 0,
                "duration": 2
            })

    # 2. Process File.csv
    file_file = os.path.join(cert_dir, "file.csv")
    if os.path.exists(file_file):
        print("  -> Parsing file.csv...")
        df_file = pd.read_csv(file_file)
        # Columns: id, date, user, pc, filename, content
        for idx, row in df_file.iterrows():
            events.append({
                "event_id": str(row.get("id", f"EVT_CERT_FILE_{idx}")),
                "timestamp": str(row.get("date")),
                "user_id": str(row.get("user")),
                "source_ip": f"10.1.{hash(str(row.get('pc'))) % 250 + 1}.{idx % 254 + 1}",
                "country": "USA",
                "device_id": str(row.get("pc")),
                "event_type": "FILE",
                "resource": str(row.get("filename", "-")),
                "action": "FILE_READ" if "open" in str(row.get("content", "")).lower() else "FILE_DOWNLOAD",
                "status": "SUCCESS",
                "session_id": f"S_CERT_{row.get('user')}_{str(row.get('date'))[:10]}",
                "bytes_transferred": int(row.get("size", np.random.randint(100_000, 50_000_000))),
                "duration": 15
            })

    # 3. Process Device.csv
    device_file = os.path.join(cert_dir, "device.csv")
    if os.path.exists(device_file):
        print("  -> Parsing device.csv...")
        df_dev = pd.read_csv(device_file)
        for idx, row in df_dev.iterrows():
            activity = str(row.get("activity", "Connect"))
            is_connect = "Connect" in activity
            events.append({
                "event_id": str(row.get("id", f"EVT_CERT_DEV_{idx}")),
                "timestamp": str(row.get("date")),
                "user_id": str(row.get("user")),
                "source_ip": f"10.1.{hash(str(row.get('pc'))) % 250 + 1}.{idx % 254 + 1}",
                "country": "USA",
                "device_id": str(row.get("pc")),
                "event_type": "DEVICE",
                "resource": "USB_REMOVABLE_MEDIA",
                "action": "USB_CONNECT" if is_connect else "USB_DISCONNECT",
                "status": "SUCCESS",
                "session_id": f"S_CERT_{row.get('user')}_{str(row.get('date'))[:10]}",
                "bytes_transferred": 0,
                "duration": 5
            })

    if not events:
        raise FileNotFoundError(f"No valid CERT log CSVs found in {cert_dir}. Required files: logon.csv, file.csv, or device.csv.")

    res_df = pd.DataFrame(events)
    res_df["timestamp"] = pd.to_datetime(res_df["timestamp"])
    res_df = res_df.sort_values(by="timestamp").reset_index(drop=True)
    res_df["timestamp"] = res_df["timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S")

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    res_df.to_csv(output_path, index=False)
    print(f"[+] Successfully converted {len(res_df)} real CERT events -> {output_path}")
    return res_df

def convert_custom_csv(input_csv: str, output_path: str = "data/raw/security_logs.csv"):
    """Converts arbitrary real-world security CSV log files to standard schema."""
    print(f"[+] Converting real-world custom security CSV: {input_csv}")
    df = pd.read_csv(input_csv)

    from src.ingestion.log_normalizer import LogNormalizer
    norm_df = LogNormalizer.normalize(df)

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    norm_df.to_csv(output_path, index=False)
    print(f"[+] Successfully normalized {len(norm_df)} real events -> {output_path}")
    return norm_df

def generate_sample_real_dataset(output_path: str = "data/sample/sample_real_logs.csv"):
    """Generates a sample pre-converted real-log format CSV based on public CERT r4.2 structure."""
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    records = []
    start_time = pd.Timestamp("2026-09-01 08:00:00")
    
    users = [f"USER_{i}" for i in range(101, 120)]
    pcs = [f"PC_{i}" for i in range(101, 120)]
    
    for i in range(500):
        t = start_time + pd.Timedelta(minutes=i*15)
        u_idx = i % len(users)
        records.append({
            "id": f"CERT_LOG_{1000+i}",
            "date": t.strftime("%m/%d/%Y %H:%M:%S"),
            "user": users[u_idx],
            "pc": pcs[u_idx],
            "activity": "Logon" if i % 10 == 0 else "FileOpen",
            "filename": f"\\\\server\\share\\document_{i % 15}.docx",
            "size": (i % 25 + 1) * 1_000_000
        })

    df = pd.DataFrame(records)
    df.to_csv(output_path, index=False)
    print(f"[+] Created sample real dataset template -> {output_path}")
    return output_path

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Convert Real-World Security Log Datasets to Standard Schema")
    parser.add_argument("--source", type=str, choices=["cert", "custom_csv", "sample_real"], default="sample_real", help="Dataset source type")
    parser.add_argument("--path", type=str, default="data/sample/sample_real_logs.csv", help="Input file or folder path")
    parser.add_argument("--output", type=str, default="data/raw/security_logs.csv", help="Destination path for pipeline execution")

    args = parser.parse_args()

    if args.source == "cert":
        convert_cert_dataset(args.path, args.output)
    elif args.source == "custom_csv":
        convert_custom_csv(args.path, args.output)
    elif args.source == "sample_real":
        sample_path = generate_sample_real_dataset()
        convert_custom_csv(sample_path, args.output)
