import subprocess
import psutil
import pickle
import numpy as np
import time
import sys
import json
import threading
from collections import defaultdict, deque
import os

# Load AI model if available (always define these variables)
ai_model = None
ai_enabled = False
try:
    with open('traffic_model.pkl', 'rb') as f:
        ai_model = pickle.load(f)
    ai_enabled = True
    print("[*] AI anomaly detection enabled.")
except Exception as e:
    print(f"[!] AI model not loaded: {e}")
    ai_enabled = False

# Update these paths as needed for your Windows install
TSHARK_PATH = r"C:\Program Files\Wireshark\tshark.exe"
SURICATA_EVE_PATH = r"C:\Program Files\Suricata\log\eve.json"

SUSPICIOUS_PORTS = {4444, 8080, 1337, 9001, 9002, 6666, 1234, 4321, 31337, 2222, 5555, 3389, 5985, 5986}
SUSPICIOUS_PROCS = [
    'certutil', 'powershell', 'cmd', 'wscript', 'cscript', 'mshta', 'bitsadmin', 'rundll32', 'regsvr32', 'wmic', 'ftp', 'telnet', 'ssh'
]

def get_local_ips():
    local_ips = set()
    for iface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if hasattr(addr, 'family') and addr.family == 2:  # AF_INET
                local_ips.add(addr.address)
    return local_ips

def extract_features(fields):
    try:
        src_port = int(fields[3]) if fields[3].isdigit() else 0
        dst_port = int(fields[4]) if fields[4].isdigit() else 0
        packet_size = int(fields[5]) if len(fields) > 5 and fields[5].isdigit() else 0
        return np.array([[src_port, dst_port, packet_size]])
    except Exception:
        return np.array([[0, 0, 0]])

def extract_suricata_features(alert):
    try:
        src_port = int(alert.get('src_port', 0))
        dst_port = int(alert.get('dest_port', 0))
        pkt_len = int(alert.get('flow', {}).get('pkts_toserver', 0)) + int(alert.get('flow', {}).get('pkts_toclient', 0))
        return np.array([[src_port, dst_port, pkt_len]])
    except Exception:
        return np.array([[0, 0, 0]])

def check_suspicious_processes():
    alerts = []
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        pname = proc.info['name']
        if pname and any(s in pname.lower() for s in SUSPICIOUS_PROCS):
            cmdline = ' '.join(proc.info['cmdline']) if proc.info['cmdline'] else ''
            alerts.append(f"[ALERT] Suspicious process: {pname} (PID {proc.info['pid']}) CMD: {cmdline}")
    return alerts

def select_interface():
    print("\n[*] Listing available network interfaces (from tshark):")
    try:
        result = subprocess.run([TSHARK_PATH, "-D"], capture_output=True, text=True)
        interfaces = result.stdout.strip().split('\n')
        for iface in interfaces:
            print(iface)
        iface_num = input("Enter the interface number to monitor (e.g., 1): ").strip()
        return iface_num
    except Exception as e:
        print(f"[!] Could not list interfaces: {e}")
        sys.exit(1)

def suricata_alert_watcher(local_ips, ai_model, ai_enabled, verbose):
    print("[*] Suricata alert watcher started.")
    # Wait for the file to exist
    while not os.path.exists(SURICATA_EVE_PATH):
        print(f"[!] Waiting for Suricata EVE JSON file at {SURICATA_EVE_PATH} ...")
        time.sleep(2)
    try:
        with open(SURICATA_EVE_PATH, "r", encoding="utf-8") as f:
            f.seek(0, os.SEEK_END)
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.5)
                    continue
                try:
                    alert = json.loads(line)
                    if alert.get("event_type") == "alert":
                        src_ip = alert.get("src_ip", "Unknown")
                        dst_ip = alert.get("dest_ip", "Unknown")
                        src_port = str(alert.get("src_port", "0"))
                        dst_port = str(alert.get("dest_port", "0"))
                        signature = alert.get("alert", {}).get("signature", "Unknown")
                        timestamp = alert.get("timestamp", "Unknown")
                        # Determine direction
                        if src_ip in local_ips and dst_ip not in local_ips:
                            direction = "outbound"
                            attacker_ip = dst_ip
                        elif dst_ip in local_ips and src_ip not in local_ips:
                            direction = "inbound"
                            attacker_ip = src_ip
                        else:
                            direction = "unknown"
                            attacker_ip = f"{src_ip} -> {dst_ip}"
                        # AI check
                        ai_flag = False
                        if ai_enabled:
                            features = extract_suricata_features(alert)
                            try:
                                prediction = ai_model.predict(features)
                                ai_flag = (prediction[0] == -1)
                            except Exception as e:
                                if verbose:
                                    print(f"[DEBUG] AI detection error (Suricata): {e}")
                        # Alert logic
                        if ai_flag:
                            print("\n=== SURICATA + AI ALERT ===")
                            print(f"Signature: {signature}")
                            print(f"Who (Hacker IP): {attacker_ip}")
                            print(f"When: {timestamp}")
                            print(f"Src Port: {src_port}  Dst Port: {dst_port}")
                            print(f"Session: ACTIVE")
                            print("===========================")
                        else:
                            print("\n=== SURICATA ALERT (Signature Only) ===")
                            print(f"Signature: {signature}")
                            print(f"Who (Hacker IP): {attacker_ip}")
                            print(f"When: {timestamp}")
                            print(f"Src Port: {src_port}  Dst Port: {dst_port}")
                            print(f"Session: ACTIVE")
                            print("===========================")
                except Exception as e:
                    if verbose:
                        print(f"[DEBUG] Suricata alert parse error: {e}")
    except Exception as e:
        print(f"[!] Suricata watcher error: {e}")

def start_suricata_prompt():
    suricata_path = input('Enter full path to suricata.exe (or press Enter for default): ').strip()
    if not suricata_path:
        suricata_path = r"C:\Program Files\Suricata\suricata.exe"
    interface = input('Enter interface number to monitor (e.g., 1): ').strip()
    config_path = input('Enter path to suricata.yaml (or press Enter for default): ').strip()
    if not config_path:
        config_path = r"C:\Program Files\Suricata\suricata.yaml"
    log_dir = input('Enter log directory (or press Enter for default): ').strip()
    if not log_dir:
        log_dir = r"C:\Program Files\Suricata\log"
    cmd = [
        suricata_path,
        "-i", interface,
        "-c", config_path,
        "-l", log_dir
    ]
    print(f"[*] Starting Suricata with: {' '.join(cmd)}")
    try:
        subprocess.Popen(cmd)
        print("[*] Suricata started. Check the log directory for eve.json.")
    except Exception as e:
        print(f"[!] Failed to start Suricata: {e}")

def run_advanced_monitoring():
    print("\n[+] BDSv1 Hybrid Detection (Suricata + AI + Heuristics + Process Monitoring)")
    verbose = input("Enable verbose debugging output? (y/n, default n): ").strip().lower() == 'y'
    monitor_ports = input("Enter ports to monitor (comma-separated, e.g., 4444,8080), or leave blank for all: ").strip()
    display_filter = "tcp"
    if monitor_ports:
        display_filter += f" && (tcp.port in {{{monitor_ports}}})"
    interface_num = select_interface()
    tshark_cmd = [
        TSHARK_PATH, "-i", interface_num, "-Y", display_filter,
        "-T", "fields",
        "-e", "frame.time", "-e", "ip.src", "-e", "ip.dst",
        "-e", "tcp.srcport", "-e", "tcp.dstport", "-e", "frame.len"
    ]
    print(f"[*] Monitoring started. Press Ctrl+C to stop.")
    if verbose:
        print("[DEBUG] Using tshark command: " + " ".join(tshark_cmd))
        print("[DEBUG] Display filter: " + display_filter)

    local_ips = get_local_ips()
    scan_tracker = defaultdict(lambda: deque(maxlen=100))  # src_ip -> dequeof dst_ports
    brute_tracker = defaultdict(lambda: deque(maxlen=100)) # src_ip+dst_port -> deque of timestamps

    # Start Suricata watcher in a thread
    suricata_thread = threading.Thread(target=suricata_alert_watcher, args=(local_ips, ai_model, ai_enabled, verbose), daemon=True)
    suricata_thread.start()

    try:
        proc = subprocess.Popen(
            tshark_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1
        )
        last_proc_check = 0
        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue
            fields = line.split('\t')
            timestamp = fields[0] if len(fields) > 0 else "Unknown"
            src_ip = fields[1] if len(fields) > 1 else "Unknown"
            dst_ip = fields[2] if len(fields) > 2 else "Unknown"
            src_port = fields[3] if len(fields) > 3 else "0"
            dst_port = fields[4] if len(fields) > 4 else "0"
            pkt_len = fields[5] if len(fields) > 5 else "0"
            if verbose:
                print(f"[DEBUG] Raw line: {line}")

            # Determine direction
            if src_ip in local_ips and dst_ip not in local_ips:
                direction = "outbound"
            elif dst_ip in local_ips and src_ip not in local_ips:
                direction = "inbound"
            else:
                direction = "unknown"

            # Heuristic: suspicious port
            if dst_port.isdigit() and int(dst_port) in SUSPICIOUS_PORTS:
                if direction == "outbound":
                    print("\n=== HEURISTIC COMPROMISE DETECTED (Reverse Shell/Outbound) ===")
                    print(f"Who (Hacker IP): {dst_ip}")
                elif direction == "inbound":
                    print("\n=== HEURISTIC COMPROMISE DETECTED (Inbound/Scan/Exploit) ===")
                    print(f"Who (Hacker IP): {src_ip}")
                else:
                    print("\n=== HEURISTIC COMPROMISE DETECTED (Unknown Direction) ===")
                    print(f"Src: {src_ip}  Dst: {dst_ip}")
                print(f"When: {timestamp}")
                print(f"Src Port: {src_port}  Dst Port: {dst_port}  Packet Size: {pkt_len}")
                print(f"Session: ACTIVE")
                print("=======================================================")

            # AI anomaly detection
            if ai_enabled:
                try:
                    features = np.array([[int(src_port), int(dst_port), int(pkt_len)]])
                    prediction = ai_model.predict(features)  # -1 = anomaly, 1 = normal
                    if prediction[0] == -1:
                        if direction == "outbound":
                            print("\n=== AI COMPROMISE DETECTED (Outbound) ===")
                            print(f"Who (Hacker IP): {dst_ip}")
                        elif direction == "inbound":
                            print("\n=== AI COMPROMISE DETECTED (Inbound) ===")
                            print(f"Who (Hacker IP): {src_ip}")
                        else:
                            print("\n=== AI COMPROMISE DETECTED (Unknown Direction) ===")
                            print(f"Src: {src_ip}  Dst: {dst_ip}")
                        print(f"When: {timestamp}")
                        print(f"Src Port: {src_port}  Dst Port: {dst_port}  Packet Size: {pkt_len}")
                        print(f"Session: ACTIVE")
                        print("==============================")
                except Exception as e:
                    if verbose:
                        print(f"[DEBUG] AI detection error: {e}")

            # Port scan detection (inbound)
            if direction == "inbound":
                scan_tracker[src_ip].append(dst_port)
                unique_ports = set(scan_tracker[src_ip])
                if len(unique_ports) > 10:
                    print("\n=== PORT SCAN DETECTED ===")
                    print(f"Scanner IP: {src_ip}")
                    print(f"Scanned Ports: {', '.join(list(unique_ports)[:15])} ...")
                    print(f"When: {timestamp}")
                    print("==========================")

            # Brute force detection (inbound, same port many times)
            if direction == "inbound":
                brute_tracker[(src_ip, dst_port)].append(timestamp)
                if len(brute_tracker[(src_ip, dst_port)]) > 20:
                    print("\n=== BRUTE FORCE ATTEMPT DETECTED ===")
                    print(f"Attacker IP: {src_ip}")
                    print(f"Target Port: {dst_port}")
                    print(f"Attempts: {len(brute_tracker[(src_ip, dst_port)])}")
                    print(f"When: {timestamp}")
                    print("===============================")

            # Periodically check for suspicious processes (every 10 seconds)
            now = time.time()
            if now - last_proc_check > 10:
                alerts = check_suspicious_processes()
                for alert in alerts:
                    print(f"\n{alert}")
                last_proc_check = now

    except KeyboardInterrupt:
        print("\n[!] Monitoring interrupted by user.")
    except FileNotFoundError:
        print("[!] tshark not found. Please install Wireshark and ensure tshark is in your PATH.")
    except Exception as e:
        print(f"[!] An error occurred: {e}")

def main():
    while True:
        print("\nBDSv1 Hybrid Monitoring Tool Menu:")
        print("1. Start Monitoring")
        print("2. Exit")
        choice = input("Select an option: ").strip()
        if choice == "1":
            run_advanced_monitoring()
        elif choice == "2":
            print("Exiting.")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
