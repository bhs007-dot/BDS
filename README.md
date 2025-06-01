  
 Blue Team Defense Tool

![BlueTeam Wallpaper]([https://via.placeholder.com/1200x400?text=Blue+Team+Defense+Wallpaper](https://netline.az/media/courses/course/2024/07/28/image_2024-07-28_223228562.png))  <!-- Replace this URL with your own image or upload one to your repo -->

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
   - Python 3.x installed (ensure it's added to your PATH).
   - Wireshark installed (download from [Wireshark website](https://www.wireshark.org/)). This provides tshark, used for packet capture.
   - Suricata installed (download from [Suricata website](https://suricata-ids.org/)). Ensure the binary is accessible at the default path or update the script.
   - Administrative privileges are required to capture network traffic and run Suricata.

2. **Dependencies:**
   - The script automatically installs required Python packages (psutil, numpy, scikit-learn, requests) if missing.
   - Run the script to handle package installation. If issues arise, install them manually using pip:
     ```
     pip install psutil numpy scikit-learn requests
     ```

3. **Script Paths:**
   - Ensure tshark and suricata paths are correct in the script (defined as constants). Update them if your installation paths differ.

4. **Troubleshooting Installation Issues:**
   - **tshark not found:** Ensure Wireshark is installed and tshark is in the specified path. If not, install Wireshark or update the path in the script.
   - **Suricata errors:** If Suricata fails to start, check that the config file exists and the rules directory is writable. You may need to run Suricata manually first to configure it.
   - **Permission errors:** Run the script as an administrator (e.g., using "Run as administrator" on Windows).
   - **Package installation failures:** If pip fails, ensure you have an internet connection and try updating pip with `python -m pip install --upgrade pip`.

5. **Initial Setup:**
   - After installation, run the script for the first time to capture traffic and train the AI model. This step is mandatory as the model is trained on your specific network baseline.

## Usage
1. **Run the Script:**
   - Execute the script using Python:
     ```
     python BDSv1.py
     ```
   - The script guides you through several steps:
     - **Traffic Capture for AI Training:** You'll be prompted to select a network interface and capture duration. This builds a baseline model for anomaly detection. Choose an interface with an active IP and a reasonable duration (e.g., 5-10 minutes for testing).
     - **Suricata Rule Update and Startup:** The script automatically downloads and extracts emerging threat rules, then starts Suricata in the background. Monitor the console for any errors.
     - **Monitoring Menu:** After setup, you'll see a menu to start monitoring.

2. **Monitoring Menu Options:**
   - **1. Start Monitoring (Realtime Alerts):** Continuous monitoring with immediate alert output. Ideal for active response scenarios.
   - **2. Start Monitoring (Batch Alerts):** Allows you to set an alert interval (e.g., 10 seconds). Alerts are batched and displayed periodically, reducing console noise.
   - **3. Exit:** Terminates the monitoring loop and stops the script.

3. **Key Interactions and Examples:**
   - **During Monitoring:** The script analyzes traffic in real-time. For example, if a port scan is detected, you might see an alert like:
     ```
     === PORT SCAN DETECTED ===
     Scanner IP: 192.168.1.100
     Scanned Ports: 80, 443, 8080 ...
     When: Jun  1, 2025 16:31:38.506123000 Arabian Standard Time
     Severity: High (AI-assessed)
     ```
     - Interpret severity levels: Critical indicates high-confidence threats, High for likely issues, Medium for potential false positives.
   - **Stopping Monitoring:** Press Ctrl+C to gracefully exit monitoring. The script will handle cleanup.
   - **Example Workflow:**
     - Select interface 1 for monitoring.
     - Start real-time alerts and observe traffic.
     - If an AI compromise is detected, the alert includes "Possible Activity" (e.g., "Possible HTTPS-based command and control") for context.

4. **Customization and Advanced Usage:**
   - **Adjusting Detection Thresholds:** Edit variables like `SUSPICIOUS_PORTS` or the brute force attempt count (currently 20) in the script code.
   - **AI Model Retraining:** Rerun traffic capture to retrain the model if your network baseline changes.
   - **Troubleshooting Common Issues:**
     - **No Alerts Triggering:** Ensure the selected interface has active traffic. Test with known scan tools during pentesting.
     - **AI Model Errors:** If the model fails to load, check that `traffic_model.pkl` exists and was trained successfully.
     - **Suricata Not Alerting:** Verify Suricata logs in the specified directory and ensure rules are updated.

5. **Best Practices for Pentesting:**
   - Always have explicit permission before running on any network.
   - Use in a controlled environment to avoid false positives.
   - Combine with other tools like Wireshark for deeper analysis.

## Changelog
- **Initial Version:** Basic traffic capture, AI training, and heuristic detections.
- **Update 1:** Added user-friendly interface selection with IP display.
- **Update 2:** Enhanced alerts with "Possible Activity" and AI-based severity for AI compromise detection.
- **Update 3:** Extended AI severity to all packet-based alerts and added heuristic severity for process alerts.
- **Latest Update:** Incorporated ASCII art banner and image wallpaper for BlueTeam theme; added detailed instructions.

## Contribution
- This script is open for contributions! Feel free to fork the repository, make improvements, and submit pull requests.
- Report issues or suggest features on the GitHub issues page.

## License
MIT License (or specify your preferred license in the script).

---

### Notes on the Image:
- I used a placeholder image URL (`https://via.placeholder.com/1200x400?text=Blue+Team+Defense+Wallpaper`) from Placehold.co, which generates a temporary image. This is for demonstration.
- **Recommendation:** Upload your own image (e.g., a BlueTeam-themed wallpaper) to your GitHub repository in a folder like `assets/`, and change the Markdown to something like `![BlueTeam Wallpaper](assets/blue_team_wallpaper.png)`. This ensures the image is hosted with your repo and doesn't rely on external links.
- If you need help finding or creating a specific image, I can suggest resources, but you'll need to handle the upload.

If this isn't what you meant or you need further changes, let me know!
