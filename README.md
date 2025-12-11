# NetShield IDS

A desktop Intrusion Detection System (IDS) that wraps around Suricata to monitor network traffic and display alerts in real-time.

## Prerequisites

Since this application wraps Suricata, you must have Suricata installed on your machine.

### 1. Install Npcap
Suricata on Windows requires Npcap for packet capture.
1. Download Npcap from [https://npcap.com/#download](https://npcap.com/#download).
2. Install it with "Install Npcap in WinPcap API-compatible Mode" checked.

### 2. Install Suricata
1. Download Suricata for Windows from [https://suricata.io/download/](https://suricata.io/download/).
2. Run the installer.
3. Note the installation path (Default is usually `C:\Program Files\Suricata`).

## How to Run

1. Ensure you have Python installed.
2. Run the application:
   ```bash
   python main.py
   ```

## Usage

1. **Configuration**:
   - **Suricata Path**: Path to `suricata.exe`.
   - **Config Path**: Path to `suricata.yaml`.
   - **Interface**: The network interface to listen on (e.g., `Ethernet`, `Wi-Fi`, or the IP address of the interface).
   - **Log Directory**: Where Suricata writes logs (specifically `eve.json`).

2. **Start IDS**:
   - Click "Start IDS".
   - The application will launch Suricata in the background.
   - It will monitor `eve.json` for new alerts.

3. **View Alerts**:
   - Alerts will appear in the table as they are detected.

## Troubleshooting

- **Suricata fails to start**: Check if the paths are correct. Try running the command manually in a terminal to see errors.
- **No alerts**: 
    - Ensure traffic is flowing.
    - Check if `eve.json` is being updated in the log directory.
    - You can test it by running a command that triggers a rule (e.g., `curl http://testmynids.org/uid/index.html`).
