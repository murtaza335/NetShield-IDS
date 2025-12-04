from flask import Flask, Response, render_template_string
import threading
import time
import json
import queue
import os
import subprocess
import signal
import sys
import atexit
import platform
import tempfile
from pathlib import Path

# Configuration
IS_WINDOWS = platform.system() == 'Windows'
SURICATA_AUTO_RESTART = True
SURICATA_RESTART_DELAY = 5

class SuricataManager:
    """Manages Suricata IDS lifecycle"""
    
    def __init__(self, interface="eth0", custom_log_dir=None):
        self.interface = interface
        self.process = None
        self.running = False
        self.restart_enabled = SURICATA_AUTO_RESTART
        
        # Setup paths
        if custom_log_dir:
            self.log_dir = Path(custom_log_dir)
        else:
            self.log_dir = Path(tempfile.gettempdir()) / "suricata_ids"
        
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.eve_log_path = self.log_dir / "eve.json"
        
        print(f"📁 Log directory: {self.log_dir}")
        print(f"📄 EVE log file: {self.eve_log_path}")
    
    def start(self):
        """Start Suricata subprocess with custom config"""
        if self.process and self.process.poll() is None:
            print("⚠️  Suricata is already running")
            return True
        
        print("=" * 70)
        print("🚀 Starting Suricata IDS...")
        print("=" * 70)
        
        # Clear old log file
        if self.eve_log_path.exists():
            print(f"🗑️  Removing old log: {self.eve_log_path}")
            try:
                self.eve_log_path.unlink()
            except Exception as e:
                print(f"⚠️  Could not remove old log: {e}")
        
        try:
            # Build Suricata command with log path override
            if IS_WINDOWS:
                # Check if WSL is available
                try:
                    subprocess.run(['wsl', '--version'], 
                                 capture_output=True, check=True, timeout=5)
                except:
                    print("❌ WSL not found! Install WSL to run Suricata on Windows.")
                    print("   Visit: https://docs.microsoft.com/windows/wsl/install")
                    return False
                
                # Convert Windows path to WSL path
                wsl_log_path = self._windows_to_wsl_path(str(self.eve_log_path))
                wsl_log_dir = self._windows_to_wsl_path(str(self.log_dir))
                
                cmd = [
                    'wsl', 'sudo', 'suricata',
                    '-i', self.interface,
                    '--set', f'default-log-dir={wsl_log_dir}',
                    '--set', f'outputs.1.eve-log.filename={wsl_log_path}',
                    '-v'
                ]
                
                print(f"🔧 Interface: {self.interface}")
                print(f"🔧 WSL Log path: {wsl_log_path}")
                print(f"🔧 Command: {' '.join(cmd[2:])}")  # Skip 'wsl sudo'
                print("\n⚠️  You may need to enter your WSL sudo password")
                
            else:
                # Linux/Unix
                cmd = [
                    'sudo', 'suricata',
                    '-i', self.interface,
                    '--set', f'default-log-dir={self.log_dir}',
                    '--set', f'outputs.1.eve-log.filename={self.eve_log_path}',
                    '-v'
                ]
                
                print(f"🔧 Interface: {self.interface}")
                print(f"🔧 Log path: {self.eve_log_path}")
            
            print()
            
            # Start Suricata
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            
            # Monitor output in background
            output_thread = threading.Thread(
                target=self._monitor_output, 
                daemon=True
            )
            output_thread.start()
            
            # Wait for initialization
            print("⏳ Waiting for Suricata to initialize...")
            time.sleep(8)
            
            # Check if still running
            if self.process.poll() is not None:
                print("❌ Suricata process terminated during startup!")
                return False
            
            # Wait for log file
            print(f"⏳ Waiting for log file: {self.eve_log_path}")
            timeout = 30
            start_time = time.time()
            
            while not self.eve_log_path.exists():
                if time.time() - start_time > timeout:
                    print(f"⚠️  Log file not created after {timeout}s")
                    print("   Suricata may still be initializing...")
                    break
                time.sleep(0.5)
            
            if self.eve_log_path.exists():
                print(f"✅ Log file created: {self.eve_log_path}")
            
            self.running = True
            print("✅ Suricata started successfully!")
            print("=" * 70)
            print()
            return True
            
        except FileNotFoundError as e:
            print(f"❌ Suricata not found! Please install it:")
            if IS_WINDOWS:
                print("   WSL: wsl sudo apt install suricata")
            else:
                print("   Ubuntu/Debian: sudo apt install suricata")
                print("   RedHat/CentOS: sudo yum install suricata")
            return False
        except Exception as e:
            print(f"❌ Error starting Suricata: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def stop(self):
        """Stop Suricata gracefully"""
        if not self.process:
            return
        
        print("\n" + "=" * 70)
        print("🛑 Stopping Suricata...")
        print("=" * 70)
        
        self.running = False
        
        try:
            # Graceful termination
            self.process.terminate()
            
            try:
                self.process.wait(timeout=15)
                print("✅ Suricata stopped gracefully")
            except subprocess.TimeoutExpired:
                print("⚠️  Force killing Suricata...")
                self.process.kill()
                self.process.wait()
                print("✅ Suricata killed")
        except Exception as e:
            print(f"⚠️  Error stopping Suricata: {e}")
        finally:
            self.process = None
    
    def restart(self):
        """Restart Suricata"""
        print("🔄 Restarting Suricata...")
        self.stop()
        time.sleep(SURICATA_RESTART_DELAY)
        return self.start()
    
    def monitor_health(self):
        """Monitor Suricata health and auto-restart if needed"""
        while self.restart_enabled:
            time.sleep(10)
            
            if self.running and self.process:
                if self.process.poll() is not None:
                    print("⚠️  Suricata process died unexpectedly!")
                    if self.restart_enabled:
                        print(f"🔄 Auto-restarting in {SURICATA_RESTART_DELAY}s...")
                        time.sleep(SURICATA_RESTART_DELAY)
                        self.start()
    
    def _monitor_output(self):
        """Monitor Suricata stdout/stderr"""
        if not self.process or not self.process.stdout:
            return
        
        for line in self.process.stdout:
            line = line.strip()
            if line:
                # Filter important messages
                if any(x in line.lower() for x in ['error', 'warning', 'failed']):
                    print(f"[Suricata] ⚠️  {line}")
                elif 'initialization' in line.lower() or 'started' in line.lower():
                    print(f"[Suricata] ℹ️  {line}")
    
    def _windows_to_wsl_path(self, windows_path):
        """Convert Windows path to WSL path"""
        # C:\Users\... -> /mnt/c/Users/...
        path = Path(windows_path)
        drive = path.drive.replace(':', '').lower()
        rest = str(path).replace(path.drive, '').replace('\\', '/')
        return f"/mnt/{drive}{rest}"


class LogTailer:
    """Tails eve.json and extracts alerts"""
    
    def __init__(self, log_path, alert_queue):
        self.log_path = Path(log_path)
        self.queue = alert_queue
        self.running = False
    
    def start(self):
        """Start tailing log file"""
        self.running = True
        thread = threading.Thread(target=self._tail, daemon=True)
        thread.start()
        print(f"📊 Log monitor started: {self.log_path}")
    
    def stop(self):
        """Stop tailing"""
        self.running = False
    
    def _tail(self):
        """Tail implementation"""
        fp = None
        last_inode = None
        
        # Wait for log file
        print(f"⏳ Waiting for log file: {self.log_path}")
        timeout = 60
        elapsed = 0
        
        while not self.log_path.exists() and elapsed < timeout:
            time.sleep(1)
            elapsed += 1
            if elapsed % 10 == 0:
                print(f"⏳ Still waiting... ({elapsed}s)")
        
        if not self.log_path.exists():
            print(f"❌ Log file not found after {timeout}s: {self.log_path}")
            return
        
        print(f"✅ Log file found, monitoring started")
        print("=" * 70)
        print()
        
        while self.running:
            try:
                # Open or reopen file
                if not fp:
                    fp = open(self.log_path, 'r', encoding='utf-8', errors='ignore')
                    try:
                        last_inode = os.fstat(fp.fileno()).st_ino
                    except:
                        last_inode = None
                    fp.seek(0, os.SEEK_END)
                
                line = fp.readline()
                
                if not line:
                    time.sleep(0.2)
                    
                    # Check for log rotation
                    try:
                        if last_inode:
                            current_inode = os.stat(self.log_path).st_ino
                            if current_inode != last_inode:
                                print("🔄 Log rotation detected, reopening...")
                                fp.close()
                                fp = None
                    except (FileNotFoundError, OSError):
                        time.sleep(0.5)
                    continue
                
                # Parse JSON
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                
                # Process alerts
                if event.get("event_type") == "alert":
                    self._process_alert(event)
                    
            except Exception as e:
                print(f"❌ Log monitor error: {e}")
                if fp:
                    try:
                        fp.close()
                    except:
                        pass
                    fp = None
                time.sleep(1)
    
    def _process_alert(self, alert):
        """Process and queue alert"""
        try:
            self.queue.put_nowait(alert)
            
            # Console output with attack details
            sig = alert.get("alert", {}).get("signature", "Unknown")
            category = alert.get("alert", {}).get("category", "Unknown")
            severity = alert.get("alert", {}).get("severity", 0)
            src = f"{alert.get('src_ip', '?')}:{alert.get('src_port', '?')}"
            dst = f"{alert.get('dest_ip', '?')}:{alert.get('dest_port', '?')}"
            timestamp = alert.get("timestamp", "")
            proto = alert.get("proto", "?")
            
            severity_icon = {1: "🔴", 2: "🟠", 3: "🟡"}.get(severity, "🔵")
            
            print(f"{severity_icon} [{timestamp}] {sig}")
            print(f"   Type: {category} | Protocol: {proto}")
            print(f"   {src} → {dst}")
            
        except queue.Full:
            # Drop oldest alert if queue full
            try:
                self.queue.get_nowait()
                self.queue.put_nowait(alert)
            except:
                pass


# Flask Application
app = Flask(__name__)
alert_queue = queue.Queue(maxsize=1000)
suricata_mgr = None
log_tailer = None


@app.route("/")
def index():
    HTML = """
<!doctype html>
<html>
<head>
    <title>Suricata IDS Dashboard</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #0f0c29 0%, #302b63 50%, #24243e 100%);
            color: #e0e0e0;
            padding: 20px;
            min-height: 100vh;
        }
        .container { max-width: 1400px; margin: 0 auto; }
        header {
            background: rgba(255, 255, 255, 0.05);
            backdrop-filter: blur(10px);
            padding: 30px;
            border-radius: 15px;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
            margin-bottom: 25px;
            border: 1px solid rgba(255, 255, 255, 0.1);
        }
        h1 {
            color: #00d4ff;
            font-size: 32px;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 15px;
            text-shadow: 0 0 20px rgba(0, 212, 255, 0.5);
        }
        #stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }
        .stat-card {
            background: rgba(255, 255, 255, 0.08);
            padding: 20px;
            border-radius: 10px;
            border: 1px solid rgba(255, 255, 255, 0.1);
            transition: transform 0.3s, box-shadow 0.3s;
        }
        .stat-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 25px rgba(0, 212, 255, 0.3);
        }
        .stat-label {
            color: #a0a0a0;
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 8px;
        }
        .stat-value {
            font-size: 28px;
            font-weight: bold;
            color: #00d4ff;
        }
        #status.connected { color: #00ff88; }
        #status.disconnected { color: #ff4444; }
        .alerts-container {
            background: rgba(255, 255, 255, 0.05);
            backdrop-filter: blur(10px);
            border-radius: 15px;
            padding: 25px;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
            border: 1px solid rgba(255, 255, 255, 0.1);
        }
        .alerts-header {
            font-size: 22px;
            color: #00d4ff;
            margin-bottom: 20px;
            padding-bottom: 15px;
            border-bottom: 2px solid rgba(0, 212, 255, 0.3);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        #events {
            list-style: none;
            padding: 0;
            max-height: 650px;
            overflow-y: auto;
        }
        #events::-webkit-scrollbar { width: 10px; }
        #events::-webkit-scrollbar-track {
            background: rgba(255, 255, 255, 0.05);
            border-radius: 5px;
        }
        #events::-webkit-scrollbar-thumb {
            background: rgba(0, 212, 255, 0.5);
            border-radius: 5px;
        }
        #events li {
            background: linear-gradient(135deg, rgba(255, 255, 255, 0.08) 0%, rgba(255, 255, 255, 0.05) 100%);
            margin: 10px 0;
            padding: 18px;
            border-radius: 10px;
            border-left: 4px solid #00d4ff;
            font-family: 'Consolas', 'Courier New', monospace;
            font-size: 13px;
            transition: all 0.3s;
            animation: slideIn 0.4s ease-out;
        }
        @keyframes slideIn {
            from { opacity: 0; transform: translateX(-30px); }
            to { opacity: 1; transform: translateX(0); }
        }
        #events li:hover {
            transform: translateX(10px);
            box-shadow: 0 5px 20px rgba(0, 212, 255, 0.4);
            background: linear-gradient(135deg, rgba(255, 255, 255, 0.12) 0%, rgba(255, 255, 255, 0.08) 100%);
        }
        .severity-1 { border-left-color: #ff4444; }
        .severity-2 { border-left-color: #ff8800; }
        .severity-3 { border-left-color: #ffdd00; }
        .timestamp {
            color: #00d4ff;
            font-weight: bold;
            text-shadow: 0 0 10px rgba(0, 212, 255, 0.5);
        }
        .ip {
            color: #00ff88;
            font-weight: 600;
        }
        .arrow {
            color: #a0a0a0;
            margin: 0 10px;
        }
        .alert-sig {
            color: #ffaa00;
            font-weight: bold;
            display: block;
            margin-top: 8px;
        }
        .protocol {
            display: inline-block;
            background: rgba(0, 212, 255, 0.2);
            padding: 3px 10px;
            border-radius: 5px;
            font-size: 11px;
            color: #00d4ff;
            margin-left: 10px;
            border: 1px solid rgba(0, 212, 255, 0.3);
        }
        .no-alerts {
            text-align: center;
            padding: 50px;
            color: #a0a0a0;
            font-style: italic;
            font-size: 16px;
        }
        .pulse {
            animation: pulse 2s infinite;
        }
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🛡️ Suricata IDS Dashboard</h1>
            <div id="stats">
                <div class="stat-card">
                    <div class="stat-label">Total Alerts</div>
                    <div class="stat-value" id="count">0</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Connection Status</div>
                    <div class="stat-value pulse" id="status" class="disconnected">Connecting...</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Last Alert Time</div>
                    <div class="stat-value" id="lastAlert" style="font-size: 16px;">Waiting...</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Uptime</div>
                    <div class="stat-value" id="uptime" style="font-size: 16px;">00:00:00</div>
                </div>
            </div>
        </header>
        <div class="alerts-container">
            <div class="alerts-header">
                <span>🚨 Live Threat Detection</span>
                <span style="font-size: 14px; color: #a0a0a0;">Real-time monitoring active</span>
            </div>
            <ul id="events">
                <li class="no-alerts">🔍 Monitoring network traffic... Waiting for security alerts</li>
            </ul>
        </div>
    </div>
    <script>
        let count = 0, firstAlert = true;
        let startTime = Date.now();
        
        // Update uptime
        setInterval(() => {
            let elapsed = Math.floor((Date.now() - startTime) / 1000);
            let hours = Math.floor(elapsed / 3600);
            let minutes = Math.floor((elapsed % 3600) / 60);
            let seconds = elapsed % 60;
            document.getElementById('uptime').textContent = 
                `${String(hours).padStart(2, '0')}:${String(minutes).padStart(2, '0')}:${String(seconds).padStart(2, '0')}`;
        }, 1000);
        
        let es = new EventSource("/stream");
        
        es.onopen = () => {
            document.getElementById("status").textContent = "Connected ✓";
            document.getElementById("status").className = "stat-value connected";
            document.getElementById("status").classList.remove("pulse");
        };
        
        es.onerror = () => {
            document.getElementById("status").textContent = "Disconnected ✗";
            document.getElementById("status").className = "stat-value disconnected pulse";
        };
        
        es.onmessage = (e) => {
            let item = JSON.parse(e.data);
            
            if (firstAlert) {
                document.getElementById("events").innerHTML = '';
                firstAlert = false;
            }
            
            let li = document.createElement("li");
            if (item.severity) {
                li.className = "severity-" + item.severity;
            }
            
            let proto = item.protocol ? `<span class="protocol">${item.protocol.toUpperCase()}</span>` : '';
            let severity_emoji = {1: '🔴', 2: '🟠', 3: '🟡'}[item.severity] || '🔵';
            
            li.innerHTML = `
                <div>
                    ${severity_emoji} <span class="timestamp">${item.timestamp}</span> ${proto}
                </div>
                <div style="margin-top: 8px;">
                    <span class="ip">${item.src_ip}:${item.src_port}</span>
                    <span class="arrow">→</span>
                    <span class="ip">${item.dest_ip}:${item.dest_port}</span>
                </div>
                <div class="alert-sig">
                    ${item.alert} 
                    <span style="color: #a0a0a0; font-size: 11px;">(SID: ${item.sid})</span>
                </div>
            `;
            
            document.getElementById("events").prepend(li);
            
            // Keep only last 100 alerts
            while (document.getElementById("events").children.length > 100) {
                document.getElementById("events").removeChild(
                    document.getElementById("events").lastChild
                );
            }
            
            count++;
            document.getElementById("count").textContent = count;
            document.getElementById("lastAlert").textContent = 
                new Date().toLocaleTimeString();
        };
    </script>
</body>
</html>
    """
    return render_template_string(HTML)


@app.route("/stream")
def stream():
    """SSE endpoint for alerts"""
    def event_stream():
        while True:
            alert = alert_queue.get()
            payload = {
                "timestamp": alert.get("timestamp"),
                "src_ip": alert.get("src_ip"),
                "src_port": alert.get("src_port"),
                "dest_ip": alert.get("dest_ip"),
                "dest_port": alert.get("dest_port"),
                "alert": alert.get("alert", {}).get("signature"),
                "sid": alert.get("alert", {}).get("signature_id"),
                "severity": alert.get("alert", {}).get("severity"),
                "category": alert.get("alert", {}).get("category"),
                "protocol": alert.get("proto")
            }
            yield f"data: {json.dumps(payload)}\n\n"
    
    return Response(event_stream(), mimetype="text/event-stream")


def cleanup():
    """Cleanup resources on exit"""
    global suricata_mgr, log_tailer
    
    print("\n🛑 Shutting down...")
    
    if log_tailer:
        log_tailer.stop()
    
    if suricata_mgr:
        suricata_mgr.stop()
    
    print("✅ Cleanup complete")


def main():
    global suricata_mgr, log_tailer
    
    print()
    print("╔" + "═" * 68 + "╗")
    print("║" + "SURICATA IDS WRAPPER & DASHBOARD".center(68) + "║")
    print("║" + "Automated IDS Management System".center(68) + "║")
    print("╚" + "═" * 68 + "╝")
    print()
    
    # Configuration
    interface = "eth0"  # Change to your network interface
    
    # You can customize log directory here
    # custom_log_dir = "/var/log/my_suricata"
    custom_log_dir = None  # Uses temp directory
    
    # Initialize Suricata manager
    suricata_mgr = SuricataManager(
        interface=interface,
        custom_log_dir=custom_log_dir
    )
    
    # Start Suricata
    if not suricata_mgr.start():
        print("\n❌ Failed to start Suricata!")
        print("\n📋 Troubleshooting:")
        print("  1. Check Suricata is installed:")
        if IS_WINDOWS:
            print("     wsl suricata --version")
        else:
            print("     suricata --version")
        print(f"  2. Verify network interface exists:")
        if IS_WINDOWS:
            print("     wsl ip link show")
        else:
            print("     ip link show")
        print(f"  3. Update 'interface' variable (currently: {interface})")
        print("  4. Ensure sudo privileges are available")
        sys.exit(1)
    
    # Start log tailer
    log_tailer = LogTailer(suricata_mgr.eve_log_path, alert_queue)
    log_tailer.start()
    
    # Start health monitor
    health_thread = threading.Thread(
        target=suricata_mgr.monitor_health,
        daemon=True
    )
    health_thread.start()
    
    # Register cleanup
    atexit.register(cleanup)
    signal.signal(signal.SIGINT, lambda s, f: sys.exit(0))
    signal.signal(signal.SIGTERM, lambda s, f: sys.exit(0))
    
    print()
    print("🌐 Dashboard: http://localhost:5000")
    print("📊 Monitoring: Real-time threat detection active")
    print("🔄 Auto-restart: " + ("Enabled" if SURICATA_AUTO_RESTART else "Disabled"))
    print("⌨️  Press Ctrl+C to stop")
    print("=" * 70)
    print()
    
    # Start Flask
    try:
        app.run(host="0.0.0.0", port=5000, threaded=True, debug=False)
    except KeyboardInterrupt:
        print("\n\n⚠️  Received shutdown signal...")
    finally:
        cleanup()
        print("\n✅ Shutdown complete\n")


if __name__ == "__main__":
    main()