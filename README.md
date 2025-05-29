![Blue Team](https://img.shields.io/badge/Blue%20Team-Defensive%20Security-blue?style=for-the-badge&logo=shield)

# BDSv1 Hybrid Monitoring Tool

A hybrid network and process monitoring tool for Windows, supporting:

- **Local network monitoring** with AI anomaly detection, heuristics, and process checks
- **Suricata IDS integration** for advanced alerting
- **Remote victim monitoring** via a simple agent over the local network

---

## Features

- **Local Monitoring:**  
  Uses `tshark` to capture network traffic, applies AI anomaly detection (if model present), detects suspicious ports, port scans, brute force attempts, and suspicious processes.

- **Suricata IDS Integration:**  
  Launches Suricata on a selected interface and watches for alerts in real time.

- **Remote Victim Monitoring:**  
  Listens for a connection from a remote agent (Python script) running on another machine in the same LAN, and displays live traffic data.

---

## Requirements

- Python 3.x
- [Wireshark](https://www.wireshark.org/) (for `tshark`)
- [Suricata](https://suricata.io/) (for IDS option)
- Python packages: `psutil`, `numpy`, `scikit-learn`

---

## Usage

1. **Clone or download this repository.**

2. **Install dependencies:**
   ```sh
   pip install psutil numpy scikit-learn
   Ensure tshark and suricata are installed and their paths are correct in the script.

(Optional) Train your AI model:

Collect normal traffic:
tshark -i <interface> -T fields -e tcp.srcport -e tcp.dstport -e frame.len -Y tcp > traffic_data.csv
Train and save the model:
___________________________________________________________________________
import numpy as np
from sklearn.ensemble import IsolationForest
import pickle

data = []
with open('traffic_data.csv', 'r') as f:
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

X = np.array(data)
model = IsolationForest(contamination=0.01, random_state=42)
model.fit(X)
with open('traffic_model.pkl', 'wb') as f:
    pickle.dump(model, f)
print("Model trained and saved as traffic_model.pkl")
__________________________________________________________________
Run the main tool:
python BDSv1.py
Notes:
Make sure you have the necessary permissions to monitor network traffic and processes.
For Suricata, use the full device string (e.g., \\Device\\NPF_{...}) when prompted.
The AI model is optional; if not present, only heuristics and process checks are used.




