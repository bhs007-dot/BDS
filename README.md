
 Blue Team Defense Tool

# Blue Team Detection Script (BDSv1)

## Overview
This Python script is a hybrid network monitoring and anomaly detection tool designed for blue team operations and penetration testing. It integrates traffic capture with tshark, intrusion detection using Suricata, and AI-based anomaly detection using an Isolation Forest model. The script helps detect potential compromises, port scans, brute force attacks, and suspicious processes, with AI-enhanced severity assessments for alerts.

## Features
- Real-time and batch monitoring of network traffic.
- AI-driven anomaly detection for traffic patterns, including severity flags (Critical, High, Medium) based on anomaly scores.
- Heuristic detections for suspicious ports, port scans, brute force attempts, and process monitoring.
- User-friendly interface selection with IP address display.
- Alert enhancements including "Possible Activity" descriptions and AI-assessed or heuristic severity levels.
- Integration with Suricata for additional IDS capabilities, with automatic rule updates.
- Consistent severity assessment across all alert types for better prioritization.

## Installation
1. **Prerequisites:**
   - Python 3.x installed.
   - Wireshark installed (ensures tshark is available at `C:\Program Files\Wireshark\tshark.exe`).
   - Suricata installed (ensures suricata is available at `C:\Program Files\Suricata\suricata.exe`).
   - Administrative privileges to run the script and access network interfaces.

2. **Dependencies:**
   - The script automatically installs required Python packages (psutil, numpy, scikit-learn, requests) if missing.
   - Run the script to handle package installation. If issues arise, install them manually using pip:
     ```
     pip install psutil numpy scikit-learn requests
     ```

3. **Script Paths:**
   - Ensure tshark and suricata paths are correct in the script (defined as constants). Update them if your installation paths differ.

## Usage
1. **Run the Script:**
   - Execute the script with Python:
     ```
     python blue_team.py
     ```
   - The script will:
     - Prompt for traffic capture to train the AI model.
     - Download and update Suricata rules.
     - Start Suricata in the background.
     - Enter the monitoring menu for real-time or batch alerts.

2. **Monitoring Menu Options:**
   - **1. Start Monitoring (Realtime Alerts):** Continuous monitoring with immediate alert output.
   - **2. Start Monitoring (Batch Alerts):** Monitoring with alerts grouped at specified intervals (e.g., every 10 seconds).
   - **3. Exit:** Quit the monitoring loop.

3. **Key Interactions:**
   - During monitoring, the script detects anomalies and outputs detailed alerts with severity levels.
   - Use Ctrl+C to interrupt monitoring gracefully.

4. **Customization:**
   - Edit the script to adjust suspicious ports, processes, or AI parameters (e.g., contamination rate in IsolationForest).
   - For advanced users, modify the `infer_possible_activity` or severity functions to fit specific environments.

## Changelog
- **Initial Version:** Basic traffic capture, AI training, and heuristic detections.
- **Update 1:** Added user-friendly interface selection with IP display.
- **Update 2:** Enhanced alerts with "Possible Activity" and AI-based severity for AI compromise detection.
- **Update 3:** Extended AI severity to all packet-based alerts (heuristic, port scan, brute force) and added heuristic severity for process alerts.
- **Latest Update:** Incorporated ASCII art banner for BlueTeam theme; ensured consistent AI flags across all alert types.

## Contribution
- This script is open for contributions! Feel free to fork the repository, make improvements, and submit pull requests.
- Report issues or suggest features on the GitHub issues page.

## License
MIT License (or specify your preferred license in the script).
