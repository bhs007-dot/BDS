# ================== BANNER & QR CODE SECTION ==================
import sys
import subprocess
import os

BANNER = r"""
██████╗ ██████╗ ███████╗    ████████╗███████╗██╗     ██╗   ██╗
██╔══██╗██╔══██╗██╔════╝    ╚══██╔══╝██╔════╝██║     ██║   ██║
██████╔╝██████╔╝█████╗         ██║   █████╗  ██║     ██║   ██║
██╔═══╝ ██╔══██╗██╔══╝         ██║   ██╔══╝  ██║     ██║   ██║
██║     ██║  ██║███████╗       ██║   ███████╗███████╗╚██████╔╝
╚═╝     ╚═╝  ╚═╝╚══════╝       ╚═╝   ╚══════╝╚══════╝ ╚═════╝ 
---------------------------------------------------------------
Blue Team Defense System (BDSv1)
(C) 2024 itsolutions007 | Instagram: @itsolutions007
Scan the QR code below to visit my Instagram!
(I have permission and am authorized for pentest)
---------------------------------------------------------------
"""

print(BANNER)

# Ensure qrcode is installed
try:
    import qrcode
except ImportError:
    print("[*] Installing qrcode library for QR code display...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "qrcode[pil]"])
    import qrcode

def show_instagram_qr():
    qr = qrcode.QRCode(border=2)
    qr.add_data("https://instagram.com/itsolutions007")
    qr.make(fit=True)
    qr.print_ascii(invert=True)
    print("Scan this QR code to visit Instagram: @itsolutions007\n")

show_instagram_qr()
# ================== END BANNER & QR CODE SECTION ==================

import requests
import tarfile
import shutil
import time
from collections import defaultdict, deque

REQUIRED_PACKAGES = [
    "psutil",
    "numpy",
    "scikit-learn",
    "requests"
]

def install_and_restart_if_needed():
    import importlib
    missing = []
    for pkg in REQUIRED_PACKAGES:
        try:
            importlib.import_module(pkg if pkg != "scikit-learn" else "sklearn")
        except ImportError:
            missing.append(pkg)
    if missing:
        print(f"[+] Installing missing packages: {', '.join(missing)}")
        subprocess.check_call([sys.executable, "-m", "pip", "install", *missing])
        print("[+] Packages installed. Restarting script...")
        os.execv(sys.executable, [sys.executable] + sys.argv)

install_and_restart_if_needed()

import pickle
import numpy as np
import threading
import json
from collections import defaultdict, deque
import psutil
from sklearn.ensemble import IsolationForest

TSHARK_PATH = r"C:\Program Files\Wireshark\tshark.exe"
SURICATA_PATH = r"C:\Program Files\Suricata\suricata.exe"
SURICATA_CONFIG = r"C:\Program Files\Suricata\suricata.yaml"
SURICATA_LOG_DIR = r"C:\Program Files\Suricata\log"
SUSPICIOUS_PORTS = {4444, 8080, 1337, 9001, 9002, 6666, 1234, 4321, 31337, 2222, 5555, 3389, 5985, 5986}  # Example suspicious ports
SUSPICIOUS_PROCS = [
    'certutil', 'powershell', 'cmd', 'wscript', 'cscript', 'mshta', 'bitsadmin', 'rundll32', 'regsvr32', 'wmic', 'ftp', 'telnet', 'ssh'
]
ALERT_COOLDOWN_SECONDS = 60  # Cooldown period in seconds for alert deduplication
BEHAVIOR_TRACKER_MAX_HISTORY = 10  # Max number of alert events to store per IP or process for behavior tracking
WAF_RULES_URL = "https://rules.emergingthreats.net/open/suricata/rules/web_attacks.rules"  # Example URL for WAF rules; can be updated

def list_interfaces_with_ips():
    interfaces = []
    iface_info = psutil.net_if_addrs()
    for idx, (iface, addrs) in enumerate(iface_info.items(), 1):
        ip = None
        for addr in addrs:
            if hasattr(addr, 'family') and addr.family == 2 and addr.address != '127.0.0.1':
                ip = addr.address
        interfaces.append((idx, iface, ip))
    return interfaces

def get_interface_number_by_name(name):
    result = subprocess.run([TSHARK_PATH, "-D"], capture_output=True, text=True)
    interfaces = result.stdout.strip().split('\n')
    for line in interfaces:
        if name in line:
            return line.split('.')[0]
    return None

def infer_possible_activity(direction, src_port, dst_port):
    # Heuristic-based inference for activity description
    src_port = int(src_port)
    dst_port = int(dst_port)
    
    if direction == "inbound":
        if dst_port == 3389:  # RDP
            return "Possible remote desktop compromise or brute force attack."
        elif dst_port == 22 or dst_port == 23:  # SSH or Telnet
            return "Likely SSH/Telnet exploit attempt or unauthorized access."
        elif dst_port == 443:
            return "Possible HTTPS-based command and control (C2) or data injection attempt."
        elif dst_port == 80:
            return "Potential web-based exploit or reconnaissance scan."
        elif dst_port in SUSPICIOUS_PORTS or src_port in SUSPICIOUS_PORTS:
            return "Likely exploit of a known vulnerable service or reverse shell initiation."
        elif src_port > 1024 and dst_port < 1024:
            return "Suspicious inbound connection, possibly a reverse shell or unauthorized access."
        else:
            return "Anomalous inbound traffic detected, could be reconnaissance or attack setup."
    elif direction == "outbound":
        if src_port == 443 or dst_port == 443:
            return "Possible data exfiltration over HTTPS or beaconing to C2 server."
        elif dst_port in SUSPICIOUS_PORTS:
            return "Outbound connection to known malicious port, indicating potential data leak or callback."
        elif src_port in SUSPICIOUS_PORTS:
            return "Suspicious outbound traffic, may involve malware communication."
        else:
            return "Anomalous outbound traffic, may involve data exfiltration or communication with external entities."
    else:
        return "Uncertain direction, possible lateral movement or internal reconnaissance."

def get_ai_severity(anomaly_score):
    # AI-based severity using anomaly score from Isolation Forest
    if anomaly_score < 0.1:
        return "Critical"
    elif anomaly_score < 0.3:
        return "High"
    else:
        return "Medium"

def infer_process_severity(process_name):
    # Heuristic severity for process-based alerts
    if process_name.lower() in ['powershell', 'cmd', 'wscript', 'cscript', 'mshta', 'bitsadmin', 'rundll32']:
        return "High"
    elif process_name.lower() in ['regsvr32', 'wmic']:
        return "Medium"
    else:
        return "Medium"  # Default for other suspicious processes

def generate_behavior_summary(behavior_data):
    # Generate a simple summary string from behavior data
    if not behavior_data['alerts']:
        return "No prior behavior tracked."
    counts = behavior_data['counts']
    summary = f"Total alerts: {len(behavior_data['alerts'])}"
    if counts['heuristic'] > 0:
        summary += f", Heuristic alerts: {counts['heuristic']}"
    if counts['ai_compromise'] > 0:
        summary += f", AI compromises: {counts['ai_compromise']}"
    if counts['port_scan'] > 0:
        summary += f", Port scans: {counts['port_scan']}"
    if counts['brute_force'] > 0:
        summary += f", Brute force attempts: {counts['brute_force']}"
    if counts['waf_threat'] > 0:
        summary += f", WAF threats: {counts['waf_threat']}"
    if counts['suspicious_process'] > 0:
        summary += f", Suspicious processes: {counts['suspicious_process']}"
    last_alert_time = behavior_data['alerts'][-1]['timestamp']
    summary += f", Last activity: {last_alert_time}"
    return summary

def countdown_timer(minutes):
    total_seconds = minutes * 60
    while total_seconds > 0:
        mins, secs = divmod(total_seconds, 60)
        if total_seconds > 10:
            print(f"[+] Capture in progress... {mins} minute(s) remaining.")
            time.sleep(60)
            total_seconds -= 60
        else:
            print(f"[+] Capture in progress... {total_seconds} second(s) remaining.")
            time.sleep(1)
            total_seconds -= 1

def capture_traffic_for_training():
    print("\n[*] Preparing to capture traffic for AI training.")
    interfaces = list_interfaces_with_ips()
    print("Available interfaces:")
    for idx, iface, ip in interfaces:
        print(f"{idx}. {iface} - IP: {ip if ip else 'No IP'}")
    choice = int(input("Select the interface number to capture traffic: ").strip())
    iface_name = interfaces[choice - 1][1]
    iface_ip = interfaces[choice - 1][2]
    iface_num = get_interface_number_by_name(iface_name)
    if not iface_num:
        print(f"[!] Could not find interface number for {iface_name}.")
        exit(1)

    print("Select capture duration unit:")
    print("1. Minutes")
    print("2. Hours")
    print("3. Days")
    print("4. Weeks")
    unit_choice = input("Enter the number for the unit (default 1): ").strip() or "1"
    unit_choice = int(unit_choice)
    unit_map = {1: "minute(s)", 2: "hour(s)", 3: "day(s)", 4: "week(s)"}
    multiplier = {1: 1, 2: 60, 3: 60*24, 4: 60*24*7}
    unit = unit_map.get(unit_choice, "minute(s)")
    factor = multiplier.get(unit_choice, 1)
    num_units = int(input(f"How many {unit} do you want to capture traffic for training? ").strip())
    total_minutes = num_units * factor

    print(f"Capturing on interface {iface_name} (IP: {iface_ip}) (number {iface_num}) for {num_units} {unit}... (I have permission and am authorized for pentest)")
    output_file = "traffic_data.csv"
    tshark_cmd = [
        TSHARK_PATH, "-i", iface_num, "-a", f"duration:{total_minutes*60}",
        "-T", "fields", "-e", "tcp.srcport", "-e", "tcp.dstport", "-e", "frame.len", "-Y", "tcp"
    ]
    # Start countdown in a separate thread
    timer_thread = threading.Thread(target=countdown_timer, args=(total_minutes,), daemon=True)
    timer_thread.start()
    with open(output_file, "w") as f:
        proc = subprocess.Popen(tshark_cmd, stdout=f, stderr=subprocess.DEVNULL, text=True)
        proc.wait()
    print(f"[*] Traffic capture complete. Data saved to {output_file}.")
    return output_file

def train_ai_model_from_file(csv_file):
    print("[*] Training AI model from captured traffic...")
    data = []
    with open(csv_file, 'r') as f:
        for line in f:
            parts = line.strip().split()
            if len(parts) != 3:
                continue
            try:
                src_port = int(parts[0])
                dst_port = int(parts[1])
                pkt_len = int(parts[2])
                data.append([src_port, dst_port, pkt_len])
            except:
                continue
    if not data:
        print("[!] No valid data found for training.")
        return None
    X = np.array(data)
    model = IsolationForest(contamination=0.01, random_state=42)
    model.fit(X)
    with open('traffic_model.pkl', 'wb') as f:
        pickle.dump(model, f)
    print("[*] Model trained and saved as traffic_model.pkl")
    return model

def load_ai_model():
    try:
        with open('traffic_model.pkl', 'rb') as f:
            model = pickle.load(f)
        print("[*] AI anomaly detection enabled.")
        return model
    except Exception as e:
        print(f"[!] AI model not loaded: {e}")
        return None

def get_local_ips():
    local_ips = set()
    for iface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if hasattr(addr, 'family') and addr.family == 2:  # AF_INET
                local_ips.add(addr.address)
    return local_ips

def check_suspicious_processes():
    alerts = []
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        pname = proc.info['name']
        if pname and any(s in pname.lower() for s in SUSPICIOUS_PROCS):
            cmdline = ' '.join(proc.info['cmdline']) if proc.info['cmdline'] else ''
            alerts.append(f"[ALERT] Suspicious process: {pname} (PID {proc.info['pid']}) CMD: {cmdline}")
    return alerts

def select_interface():
    print("\n[*] Listing available network interfaces with IPs:")
    interfaces = list_interfaces_with_ips()
    for idx, iface, ip in interfaces:
        print(f"{idx}. {iface} - IP: {ip if ip else 'No IP'}")
    choice = int(input("Select the interface number to use: ").strip())
    iface_name = interfaces[choice - 1][1]  # Return the interface name
    return iface_name

def run_advanced_monitoring(realtime=True, interval=10, waf_mode=False):
    print("\n[+] BDSv1 Hybrid Detection (AI + Heuristics + Process Monitoring with Behavior Tracking)")
    if waf_mode:
        print("[*] WAF Monitoring Mode: Focusing on web threats detection.")
    verbose = input("Enable verbose debugging output? (y/n, default n): ").strip().lower() == 'y'
    monitor_ports = input("Enter ports to monitor (comma-separated, e.g., 80,443 for web, or leave blank for all): ").strip()
    display_filter = "tcp"
    if waf_mode:
        display_filter = "http or tls"  # Focus on HTTP/HTTPS for WAF
    if monitor_ports:
        display_filter += f" && (tcp.port in {{{monitor_ports}}})"
    
    # Select interface with IP display
    iface_name = select_interface()
    iface_num = get_interface_number_by_name(iface_name)
    if not iface_num:
        print(f"[!] Could not find interface number for {iface_name}. Exiting.")
        return
    
    tshark_cmd = [
        TSHARK_PATH, "-i", iface_num, "-Y", display_filter,
        "-T", "fields",
        "-e", "frame.time", "-e", "ip.src", "-e", "ip.dst",
        "-e", "tcp.srcport", "-e", "tcp.dstport", "-e", "frame.len", "-e", "http.request.method" if waf_mode else ""
    ]
    print(f"[*] Monitoring started on interface {iface_name}. Press Ctrl+C to stop.")
    if verbose:
        print("[DEBUG] Using tshark command: " + " ".join(tshark_cmd))
        print("[DEBUG] Display filter: " + display_filter)

    local_ips = get_local_ips()
    scan_tracker = defaultdict(lambda: deque(maxlen=100))  # src_ip -> deque of dst_ports
    brute_tracker = defaultdict(lambda: deque(maxlen=100)) # src_ip+dst_port -> deque of timestamps
    alert_cooldown = defaultdict(float)  # Track last alert time for (IP, alert_type) or (process_name, "suspicious_process")
    behavior_tracker = defaultdict(lambda: {'alerts': [], 'counts': defaultdict(int)})  # IP or process -> {alerts: list, counts: dict}

    alerts = []
    last_update = time.time()
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
            http_method = fields[6] if len(fields) > 6 and waf_mode else "N/A"  # HTTP method for WAF mode
            if verbose:
                print(f"[DEBUG] Raw line: {line}")

            # Determine direction
            if src_ip in local_ips and dst_ip not in local_ips:
                direction = "outbound"
                hacker_ip = dst_ip  # Outbound: remote IP is the potential hacker
            elif dst_ip in local_ips and src_ip not in local_ips:
                direction = "inbound"
                hacker_ip = src_ip  # Inbound: source IP is the potential hacker
            else:
                direction = "unknown"
                hacker_ip = src_ip or dst_ip  # Use source or destination as fallback

            alert_msgs = []

            # WAF-specific threat detection if in WAF mode
            if waf_mode and (int(dst_port) in [80, 443] or int(src_port) in [80, 443]):  # Focus on web ports
                alert_type = "waf_threat"
                if time.time() - alert_cooldown.get((hacker_ip, alert_type), 0) > ALERT_COOLDOWN_SECONDS:
                    alert_cooldown[(hacker_ip, alert_type)] = time.time()
                    # Simple heuristic for WAF: check for suspicious HTTP methods or patterns (can be enhanced)
                    if "POST" in http_method or "GET" in http_method:  # Example: flag common web attack vectors
                        severity = "High"  # Default severity for WAF alerts; can be AI-enhanced if needed
                        alert_msgs.append(f"\n=== WAF THREAT DETECTED ===\nHacker IP: {hacker_ip}")
                        alert_msgs.append(f"When: {timestamp}")
                        alert_msgs.append(f"HTTP Method: {http_method}")
                        alert_msgs.append(f"Src Port: {src_port}  Dst Port: {dst_port}")
                        alert_msgs.append(f"Possible Threat: Suspicious web request (e.g., potential SQLi or XSS)")
                        alert_msgs.append(f"Severity: {severity} (heuristic)")  # Rely on Suricata for more advanced detection
                        # Update behavior tracker
                        behavior_tracker[hacker_ip]['alerts'].append({'type': alert_type, 'timestamp': timestamp})
                        if len(behavior_tracker[hacker_ip]['alerts']) > BEHAVIOR_TRACKER_MAX_HISTORY:
                            behavior_tracker[hacker_ip]['alerts'].pop(0)  # Remove oldest entry
                        behavior_tracker[hacker_ip]['counts'][alert_type] += 1
                        behavior_summary = generate_behavior_summary(behavior_tracker[hacker_ip])
                        alert_msgs.append(f"Behavior Summary: {behavior_summary}")
                        alert_msgs.append("==========================")

            # Heuristic: suspicious port with AI severity, deduplication, and behavior tracking
            if dst_port.isdigit() and int(dst_port) in SUSPICIOUS_PORTS:
                alert_type = "heuristic"
                if time.time() - alert_cooldown.get((hacker_ip, alert_type), 0) > ALERT_COOLDOWN_SECONDS:
                    alert_cooldown[(hacker_ip, alert_type)] = time.time()
                    if ai_model:
                        try:
                            features = np.array([[int(src_port), int(dst_port), int(pkt_len)]])
                            anomaly_score = ai_model.decision_function(features)[0]
                            severity = get_ai_severity(anomaly_score)
                        except Exception as e:
                            if verbose:
                                print(f"[DEBUG] AI severity error for heuristic alert: {e}")
                            severity = "Medium"  # Fallback
                    else:
                        severity = "Medium"  # No AI model
                    if direction == "outbound":
                        alert_msgs.append(f"\n=== HEURISTIC COMPROMISE DETECTED (Reverse Shell/Outbound) ===\nWho (Hacker IP): {hacker_ip}")
                    elif direction == "inbound":
                        alert_msgs.append(f"\n=== HEURISTIC COMPROMISE DETECTED (Inbound/Scan/Exploit) ===\nWho (Hacker IP): {hacker_ip}")
                    else:
                        alert_msgs.append(f"\n=== HEURISTIC COMPROMISE DETECTED (Unknown Direction) ===\nSrc: {src_ip}  Dst: {dst_ip}")
                    alert_msgs.append(f"When: {timestamp}")
                    alert_msgs.append(f"Src Port: {src_port}  Dst Port: {dst_port}  Packet Size: {pkt_len}")
                    alert_msgs.append(f"Severity: {severity} (AI-assessed)" if ai_model else f"Severity: {severity} (heuristic)")
                    # Update behavior tracker
                    behavior_tracker[hacker_ip]['alerts'].append({'type': alert_type, 'timestamp': timestamp})
                    if len(behavior_tracker[hacker_ip]['alerts']) > BEHAVIOR_TRACKER_MAX_HISTORY:
                        behavior_tracker[hacker_ip]['alerts'].pop(0)  # Remove oldest entry
                    behavior_tracker[hacker_ip]['counts'][alert_type] += 1
                    behavior_summary = generate_behavior_summary(behavior_tracker[hacker_ip])
                    alert_msgs.append(f"Behavior Summary: {behavior_summary}")
                    alert_msgs.append(f"Session: ACTIVE")
                    alert_msgs.append("=======================================================")

            # AI anomaly detection with inferred activity and AI severity, deduplication, and behavior tracking
            if ai_model:
                try:
                    features = np.array([[int(src_port), int(dst_port), int(pkt_len)]])
                    prediction = ai_model.predict(features)  # -1 = anomaly, 1 = normal
                    if prediction[0] == -1:  # Anomaly detected
                        alert_type = "ai_compromise"
                        if time.time() - alert_cooldown.get((hacker_ip, alert_type), 0) > ALERT_COOLDOWN_SECONDS:
                            alert_cooldown[(hacker_ip, alert_type)] = time.time()
                            anomaly_score = ai_model.decision_function(features)[0]
                            activity = infer_possible_activity(direction, src_port, dst_port)
                            severity = get_ai_severity(anomaly_score)
                            if direction == "outbound":
                                alert_msgs.append(f"\n=== AI COMPROMISE DETECTED (Outbound) ===\nWho (Hacker IP): {hacker_ip}")
                            elif direction == "inbound":
                                alert_msgs.append(f"\n=== AI COMPROMISE DETECTED (Inbound) ===\nWho (Hacker IP): {hacker_ip}")
                            else:
                                alert_msgs.append(f"\n=== AI COMPROMISE DETECTED (Unknown Direction) ===\nSrc: {src_ip}  Dst: {dst_ip}")
                            alert_msgs.append(f"When: {timestamp}")
                            alert_msgs.append(f"Src Port: {src_port}  Dst Port: {dst_port}  Packet Size: {pkt_len}")
                            alert_msgs.append(f"Possible Activity: {activity}")
                            alert_msgs.append(f"Severity: {severity} (AI-assessed)")
                            # Update behavior tracker
                            behavior_tracker[hacker_ip]['alerts'].append({'type': alert_type, 'timestamp': timestamp})
                            if len(behavior_tracker[hacker_ip]['alerts']) > BEHAVIOR_TRACKER_MAX_HISTORY:
                                behavior_tracker[hacker_ip]['alerts'].pop(0)  # Remove oldest entry
                            behavior_tracker[hacker_ip]['counts'][alert_type] += 1
                            behavior_summary = generate_behavior_summary(behavior_tracker[hacker_ip])
                            alert_msgs.append(f"Behavior Summary: {behavior_summary}")
                            alert_msgs.append(f"Session: ACTIVE")
                            alert_msgs.append("==============================")
                except Exception as e:
                    if verbose:
                        print(f"[DEBUG] AI detection error: {e}")

            # Port scan detection with AI severity, deduplication, and behavior tracking
            if direction == "inbound":
                scan_tracker[src_ip].append(dst_port)
                unique_ports = set(scan_tracker[src_ip])
                if len(unique_ports) > 10:
                    alert_type = "port_scan"
                    if time.time() - alert_cooldown.get((hacker_ip, alert_type), 0) > ALERT_COOLDOWN_SECONDS:
                        alert_cooldown[(hacker_ip, alert_type)] = time.time()
                        if ai_model:
                            try:
                                features = np.array([[int(src_port), int(dst_port), int(pkt_len)]])
                                anomaly_score = ai_model.decision_function(features)[0]
                                severity = get_ai_severity(anomaly_score)
                            except Exception as e:
                                if verbose:
                                    print(f"[DEBUG] AI severity error for port scan: {e}")
                                severity = "Medium"  # Fallback
                        else:
                            severity = "Medium"  # No AI model
                        alert_msgs.append(f"\n=== PORT SCAN DETECTED ===\nScanner IP: {hacker_ip}")
                        alert_msgs.append(f"Scanned Ports: {', '.join(list(unique_ports)[:15])} ...")
                        alert_msgs.append(f"When: {timestamp}")
                        alert_msgs.append(f"Severity: {severity} (AI-assessed)" if ai_model else f"Severity: {severity} (heuristic)")
                        # Update behavior tracker
                        behavior_tracker[hacker_ip]['alerts'].append({'type': alert_type, 'timestamp': timestamp})
                        if len(behavior_tracker[hacker_ip]['alerts']) > BEHAVIOR_TRACKER_MAX_HISTORY:
                            behavior_tracker[hacker_ip]['alerts'].pop(0)  # Remove oldest entry
                        behavior_tracker[hacker_ip]['counts'][alert_type] += 1
                        behavior_summary = generate_behavior_summary(behavior_tracker[hacker_ip])
                        alert_msgs.append(f"Behavior Summary: {behavior_summary}")
                        alert_msgs.append("==========================")

            # Brute force detection with AI severity, deduplication, and behavior tracking
            if direction == "inbound":
                brute_tracker[(src_ip, dst_port)].append(timestamp)
                if len(brute_tracker[(src_ip, dst_port)]) > 20:
                    alert_type = "brute_force"
                    if time.time() - alert_cooldown.get((hacker_ip, alert_type), 0) > ALERT_COOLDOWN_SECONDS:
                        alert_cooldown[(hacker_ip, alert_type)] = time.time()
                        if ai_model:
                            try:
                                features = np.array([[int(src_port), int(dst_port), int(pkt_len)]])
                                anomaly_score = ai_model.decision_function(features)[0]
                                severity = get_ai_severity(anomaly_score)
                            except Exception as e:
                                if verbose:
                                    print(f"[DEBUG] AI severity error for brute force: {e}")
                                severity = "High"  # Fallback for brute force
                        else:
                            severity = "High"  # No AI model, default high for brute force
                        alert_msgs.append(f"\n=== BRUTE FORCE ATTEMPT DETECTED ===\nAttacker IP: {hacker_ip}")
                        alert_msgs.append(f"Target Port: {dst_port}")
                        alert_msgs.append(f"Attempts: {len(brute_tracker[(src_ip,dst_port)])}")
                        alert_msgs.append(f"When: {timestamp}")
                        alert_msgs.append(f"Severity: {severity} (AI-assessed)" if ai_model else f"Severity: {severity} (heuristic)")
                        # Update behavior tracker
                        behavior_tracker[hacker_ip]['alerts'].append({'type': alert_type, 'timestamp': timestamp})
                        if len(behavior_tracker[hacker_ip]['alerts']) > BEHAVIOR_TRACKER_MAX_HISTORY:
                            behavior_tracker[hacker_ip]['alerts'].pop(0)  # Remove oldest entry
                        behavior_tracker[hacker_ip]['counts'][alert_type] += 1
                        behavior_summary = generate_behavior_summary(behavior_tracker[hacker_ip])
                        alert_msgs.append(f"Behavior Summary: {behavior_summary}")
                        alert_msgs.append("===============================")

            # Periodically check for suspicious processes with heuristic severity, deduplication, and behavior tracking
            now = time.time()
            if now - last_proc_check > 10:
                proc_alerts = check_suspicious_processes()
                for alert in proc_alerts:
                    # Extract process name from alert string, e.g., "Suspicious process: powershell (PID 1234) CMD: ..."
                    process_name = alert.split()[3]  # Assumes format is consistent
                    alert_type = "suspicious_process"
                    if time.time() - alert_cooldown.get((process_name, alert_type), 0) > ALERT_COOLDOWN_SECONDS:
                        alert_cooldown[(process_name, alert_type)] = time.time()
                        heuristic_severity = infer_process_severity(process_name)
                        process_alert_msg = f"{alert}\nSeverity: {heuristic_severity} (heuristic)"
                        # For process alerts, use process name as the key for behavior tracking
                        behavior_tracker[process_name]['alerts'].append({'type': alert_type, 'timestamp': timestamp})
                        if len(behavior_tracker[process_name]['alerts']) > BEHAVIOR_TRACKER_MAX_HISTORY:
                            behavior_tracker[process_name]['alerts'].pop(0)  # Remove oldest entry
                        behavior_tracker[process_name]['counts'][alert_type] += 1
                        behavior_summary = generate_behavior_summary(behavior_tracker[process_name])
                        process_alert_msg += f"\nBehavior Summary: {behavior_summary}"
                        alert_msgs.append(f"\n{process_alert_msg}")
                last_proc_check = now

            # Output alerts
            if alert_msgs:
                alert_output = "\n".join(alert_msgs)
                if realtime:
                    print(alert_output)
                else:
                    alerts.append(alert_output)
                    if time.time() - last_update >= interval:
                        print("\n--- Batch Alerts ---")
                        for a in alerts:
                            print(a)
                        alerts.clear()
                        last_update = time.time()

    except KeyboardInterrupt:
        print("\n[!] Monitoring interrupted by user.")
    except FileNotFoundError:
        print("[!] tshark not found. Please install Wireshark and ensure tshark is in your PATH.")
    except Exception as e:
        print(f"[!] An error occurred: {e}")

def download_suricata_rules():
    print("[*] Downloading and updating Suricata rules...")
    rules_url = "https://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz"  # General rules
    waf_rules_url = WAF_RULES_URL  # WAF-specific rules
    rules_dir = os.path.dirname(SURICATA_CONFIG) + "/rules"  # Typically C:\Program Files\Suricata\rules
    temp_file_general = "emerging_rules.tar.gz"
    temp_file_waf = "waf_rules.tar.gz"  # Separate file for WAF rules

    # Ensure rules directory exists
    if not os.path.exists(rules_dir):
        os.makedirs(rules_dir)

    try:
        # Download and extract general rules
        response = requests.get(rules_url, stream=True)
        if response.status_code == 200:
            with open(temp_file_general, 'wb') as f:
                for chunk in response.iter_content(chunk_size=128):
                    f.write(chunk)
            with tarfile.open(temp_file_general, 'r:gz') as tar:
                tar.extractall(path=rules_dir)
            os.remove(temp_file_general)
        else:
            print(f"[!] Failed to download general rules. Status code: {response.status_code}.")

        # Download and extract WAF rules
        response_waf = requests.get(waf_rules_url, stream=True)
        if response_waf.status_code == 200:
            with open(temp_file_waf, 'wb') as f:
                for chunk in response_waf.iter_content(chunk_size=128):
                    f.write(chunk)
            with tarfile.open(temp_file_waf, 'r:gz') as tar:
                tar.extractall(path=rules_dir)
            os.remove(temp_file_waf)
            print("[+] WAF rules downloaded and extracted successfully.")
        else:
            print(f"[!] Failed to download WAF rules. Status code: {response_waf.status_code}. Please check the URL or download manually.")
    except Exception as e:
        print(f"[!] Error downloading or extracting rules: {e}. Continuing with available rules.")

def start_suricata_prompt():
    print("\n[+] Starting SuricataIDS in background with interface selection and WAF rules loaded.")
    interfaces = list_interfaces_with_ips()
    print("Available interfaces for Suricata:")
    for idx, iface, ip in interfaces:
        print(f"{idx}. {iface} - IP: {ip if ip else 'No IP'}")
    choice = int(input("Select the interface number for Suricata: ").strip())
    iface_name = interfaces[choice - 1][1]  # Get the interface name from selection
    
    # For Suricata, we might need the full device string, but we'll use the name for simplicity
    # If issues arise, user can update SURICATA_PATH or config
    suricata_cmd = [
        SURICATA_PATH,
        "-i", iface_name,  # Use the selected interface name
        "-c", SURICATA_CONFIG,
        "-l", SURICATA_LOG_DIR
    ]
    print(f"[*] Suricata starting on interface {iface_name} in background with WAF capabilities. Alerts will be monitored.")
    # Start Suricata in background (non-blocking)
    suricata_proc = subprocess.Popen(suricata_cmd)
    # Start watcher thread for alerts
    watcher_thread = threading.Thread(target=suricata_alert_watcher, daemon=True)
    watcher_thread.start()

def suricata_alert_watcher():
    alert_file = os.path.join(SURICATA_LOG_DIR, "fast.log")
    eve_file = os.path.join(SURICATA_LOG_DIR, "eve.json")
    print("[*] Watching Suricata alerts in background...")
    seen = set()
    while True:
        try:
            if os.path.exists(alert_file):
                with open(alert_file, "r") as f:
                    for line in f:
                        if line not in seen:
                            print("[SURICATA ALERT]", line.strip())
                            seen.add(line)
            if os.path.exists(eve_file):
                with open(eve_file, "r") as f:
                    for line in f:
                        if line not in seen:
                            try:
                                data = json.loads(line)
                                if "alert" in data:
                                    print("[SURICATA EVE ALERT]", data)
                            except Exception:
                                pass
                            seen.add(line)
            time.sleep(2)
        except Exception:
            time.sleep(2)

def monitoring_menu():
    while True:
        print("\nMonitoring Menu:")
        print("1. Start Monitoring (Realtime Alerts)")
        print("2. Start Monitoring (Batch Alerts)")
        print("3. WAF Monitoring (Web Threats Detection)")
        print("4. Exit")
        choice = input("Select an option: ").strip()
        if choice == "1":
            run_advanced_monitoring(realtime=True, waf_mode=False)
        elif choice == "2":
            interval = int(input("Enter alert update interval in seconds: ").strip())
            run_advanced_monitoring(realtime=False, interval=interval, waf_mode=False)
        elif choice == "3":
            run_advanced_monitoring(realtime=True, waf_mode=True)  # WAF mode with real-time for simplicity; can be extended
        elif choice == "4":
            print("Exiting.")
            break
        else:
            print("Invalid choice. Please try again.")

def main():
    # Step 1: Capture traffic for training
    csv_file = capture_traffic_for_training()
    # Step 2: Train AI model
    global ai_model
    ai_model = train_ai_model_from_file(csv_file)
    if ai_model is None:
        print("[!] AI model training failed. Exiting.")
        return
    # Step 3: Download and update Suricata rules including WAF rules
    download_suricata_rules()
    # Step 4: Start Suricata in background with interface selection
    print("\n[+] Setting up and starting Suricata IDS with WAF capabilities before monitoring options.")
    start_suricata_prompt()
    # Step 5: Go to monitoring menu (with Suricata already running)
    monitoring_menu()

if __name__ == "__main__":
    main()
