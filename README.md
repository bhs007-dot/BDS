<p align="center">
  <img src="https://images.unsplash.com/photo-1510511459019-5dda7724fd87?auto=format&fit=crop&w=1000&q=80" alt="Blue Team Cybersecurity" width="800"/>
</p>

# Enhanced Blue Team Compromise Detection Tool (BDSv1)

A Windows-compatible, real-time network and process monitoring tool for blue teams. Detects reverse shells, port scans, brute force attempts, suspicious processes, and more using AI, heuristics, and live traffic analysis.

## Features

- **Network Traffic Monitoring** (via `tshark`)
- **Reverse Shell & Outbound Attack Detection**
- **Inbound Attack & Port Scan Detection**
- **Brute Force Attempt Detection**
- **Suspicious Process Monitoring** (LOLBins, shells, etc.)
- **AI/ML Anomaly Detection** (optional, with pre-trained model)
- **Verbose Debugging Output**
- **User-friendly Interface Selection**

## Requirements

- **Python 3.7+**
- [Wireshark](https://www.wireshark.org/download.html) (with `tshark.exe`)
- Python packages: `psutil`, `numpy`
- *(Optional)* `scikit-learn` and a pre-trained `traffic_model.pkl` for AI detection

## Installation

1. **Install Wireshark**  
   Download and install Wireshark for Windows. Ensure `tshark.exe` is installed and note its path (default: `C:\Program Files\Wireshark\tshark.exe`).

2. **Install Python Packages**  
   ```bash
   pip install psutil numpy
   # Optional for AI detection:
   pip install scikit-learn
   git clone https://github.com/yourusername/BDSv1.git
cd BDSv1
(Optional) Add AI Model

Place your pre-trained traffic_model.pkl in the script directory for anomaly detection.

Usage
Open Command Prompt or PowerShell as Administrator (required for packet capture).

Start the Tool

bash

Copy
python BDSv1.py
Follow Prompts

Select network interface (listed by the tool)
Enable/disable verbose output
Specify ports to monitor (or leave blank for all)
Monitor Alerts

Reverse shell/outbound attacks: Attacker IP is destination
Inbound scans/attacks: Attacker IP is source
Port scans, brute force, and suspicious processes are flagged in real time
Example Output

Copy
=== PORT SCAN DETECTED ===
Scanner IP: 192.168.1.100
Scanned Ports: 22, 80, 443, 3389, ...
When: 2024-05-29 12:34:56
==========================
Customization
Edit TSHARK_PATH in the script if Wireshark is installed in a non-default location.
Adjust detection thresholds (e.g., number of ports for scan detection) in the script as needed.
Notes
For best results, run on the host you wish to monitor.
The tool is designed for blue team/defensive use in authorized environments.
