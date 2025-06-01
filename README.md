# Blue Team Detection Script (BDSv1)

## Overview
This Python script is a comprehensive blue team tool designed for authorized penetration testers and cybersecurity professionals. It provides hybrid intrusion detection using AI-based anomaly detection, heuristic rules, and process monitoring. The script captures network traffic for AI training, detects potential compromises, and integrates Suricata IDS for enhanced alerting. It's built for ethical hacking and security testing, ensuring compliance with authorized activities.

Key features:
- Automatic installation of required Python packages.
- Flexible traffic capture duration (minutes, hours, days, weeks).
- AI model training using Isolation Forest for anomaly detection.
- Heuristic detection for suspicious ports and behaviors.
- Integration with Suricata IDS, which starts automatically in the background.
- Simplified monitoring menu with realtime and batch alert options.
- Cross-compatible with Windows (using Wireshark and Suricata).

As a certified pentester (e.g., OSCP, CEH), this tool helps streamline your defensive security assessments.

## Requirements
- Python 3.6 or higher.
- Wireshark installed (for tshark.exe).
- Suricata IDS installed (for suricata.exe). Ensure it's accessible via the default path or update the script.
- Dependencies are automatically installed by the script, but you may need pip and internet access for the first run.

## Installation
1. Clone or download this repository to your local machine.
2. Ensure Wireshark and Suricata are installed:
   - Wireshark: Download from [https://www.wireshark.org/](https://www.wireshark.org/) and install.
   - Suricata: Download from [https://suricata-ids.org/download/](https://suricata-ids.org/download/). On Windows, use WSL for easier setup if needed.
3. Run the script with Python:
4. python BDSv1.py
5. The script will automatically check and install Python packages like `psutil`, `numpy`, and `scikit-learn` if missing.

## Usage
1. **Run the Script:** Execute `python blue_team.py`. It will:
- Prompt you to select a network interface and capture duration for AI training.
- Train an AI model based on captured traffic.
- Automatically start Suricata IDS in the background and begin monitoring its alerts.
- Enter the monitoring menu.

2. **Monitoring Menu:**
- **Option 1: Start Monitoring (Realtime Alerts)**: Runs continuous monitoring with immediate alerts for anomalies, suspicious ports, port scans, brute force attempts, and Suricata events.
- **Option 2: Start Monitoring (Batch Alerts)**: Similar to realtime but batches alerts at specified intervals for less noise.
- **Option 3: Exit**: Quits the script.

3. **Example Workflow:**
- During capture, the script counts down the time and saves data.
- In monitoring mode, it detects threats and prints alerts. Press Ctrl+C to stop monitoring.
- Suricata alerts are handled in the background and printed as they occur.

## Configuration
- **Paths:** Update constants in the script if your installations differ:
- `TSHARK_PATH`: Path to tshark.exe (e.g., `r"C:\Program Files\Wireshark\tshark.exe"`).
- `SURICATA_PATH`: Path to suricata.exe (e.g., `r"C:\Program Files\Suricata\suricata.exe"`).
- `SURICATA_CONFIG`: Path to suricata.yaml configuration file.
- `SURICATA_LOG_DIR`: Directory for Suricata logs.

- **Suspicious Ports and Processes:** You can modify the lists `SUSPICIOUS_PORTS` and `SUSPICIOUS_PROCS` in the script to customize detection.

## Notes
- This script is intended for authorized use only. Ensure you have permission before running network captures or monitoring.
- For contributions or issues, feel free to open a pull request or report on GitHub.

## License
This script is provided under the MIT License. See the LICENSE file for details.
