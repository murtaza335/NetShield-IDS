import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import subprocess
import threading
import time
import json
import os
import sys

# Default Configuration for Windows
DEFAULT_SURICATA_PATH = r"C:\Program Files\Suricata\suricata.exe"
DEFAULT_CONFIG_PATH = r"C:\Program Files\Suricata\suricata.yaml"
# Use a local logs directory to avoid Permission Denied errors in Program Files
DEFAULT_LOG_DIR = os.path.join(os.getcwd(), "logs")
EVE_JSON_FILE = "eve.json"

class NetShieldIDS:
    def __init__(self, root):
        self.root = root
        self.root.title("NetShield IDS - Suricata Wrapper")
        self.root.geometry("1000x700")
        
        self.is_running = False
        self.suricata_process = None
        self.stop_event = threading.Event()

        self.setup_ui()

    def setup_ui(self):
        # --- Configuration Frame ---
        config_frame = ttk.LabelFrame(self.root, text="Configuration", padding="10")
        config_frame.pack(fill="x", padx=10, pady=5)

        # Suricata Executable
        ttk.Label(config_frame, text="Suricata Path:").grid(row=0, column=0, sticky="w")
        self.suricata_path_var = tk.StringVar(value=DEFAULT_SURICATA_PATH)
        ttk.Entry(config_frame, textvariable=self.suricata_path_var, width=50).grid(row=0, column=1, padx=5, pady=2)

        # Config File
        ttk.Label(config_frame, text="Config Path:").grid(row=1, column=0, sticky="w")
        self.config_path_var = tk.StringVar(value=DEFAULT_CONFIG_PATH)
        ttk.Entry(config_frame, textvariable=self.config_path_var, width=50).grid(row=1, column=1, padx=5, pady=2)

        # Interface
        ttk.Label(config_frame, text="Interface (e.g., Ethernet):").grid(row=2, column=0, sticky="w")
        self.interface_var = tk.StringVar(value="Ethernet")
        ttk.Entry(config_frame, textvariable=self.interface_var, width=20).grid(row=2, column=1, sticky="w", padx=5, pady=2)

        # Log Directory
        ttk.Label(config_frame, text="Log Directory:").grid(row=3, column=0, sticky="w")
        self.log_dir_var = tk.StringVar(value=DEFAULT_LOG_DIR)
        ttk.Entry(config_frame, textvariable=self.log_dir_var, width=50).grid(row=3, column=1, padx=5, pady=2)

        # Buttons
        btn_frame = ttk.Frame(config_frame)
        btn_frame.grid(row=4, column=0, columnspan=2, pady=10)
        
        self.start_btn = ttk.Button(btn_frame, text="Start IDS", command=self.start_ids)
        self.start_btn.pack(side="left", padx=5)
        
        self.stop_btn = ttk.Button(btn_frame, text="Stop IDS", command=self.stop_ids, state="disabled")
        self.stop_btn.pack(side="left", padx=5)

        self.list_iface_btn = ttk.Button(btn_frame, text="List Interfaces", command=self.list_interfaces)
        self.list_iface_btn.pack(side="left", padx=5)

        self.test_btn = ttk.Button(btn_frame, text="Test IDS", command=self.test_ids)
        self.test_btn.pack(side="left", padx=5)

        self.update_rules_btn = ttk.Button(btn_frame, text="Update Rules", command=self.update_rules)
        self.update_rules_btn.pack(side="left", padx=5)

        self.fix_config_btn = ttk.Button(btn_frame, text="Fix Config", command=self.fix_config)
        self.fix_config_btn.pack(side="left", padx=5)

        self.ping_rule_btn = ttk.Button(btn_frame, text="Allow Local Attacks", command=self.allow_local_attacks)
        self.ping_rule_btn.pack(side="left", padx=5)

        # --- Alerts View ---
        alert_frame = ttk.LabelFrame(self.root, text="Live Alerts", padding="10")
        alert_frame.pack(fill="both", expand=True, padx=10, pady=5)

        columns = ("timestamp", "src_ip", "src_port", "dest_ip", "dest_port", "category", "signature", "severity")
        self.tree = ttk.Treeview(alert_frame, columns=columns, show="headings")
        
        # Define headings
        self.tree.heading("timestamp", text="Timestamp")
        self.tree.heading("src_ip", text="Source IP")
        self.tree.heading("src_port", text="Src Port")
        self.tree.heading("dest_ip", text="Dest IP")
        self.tree.heading("dest_port", text="Dst Port")
        self.tree.heading("category", text="Classification")
        self.tree.heading("signature", text="Signature")
        self.tree.heading("severity", text="Sev")

        # Define columns width
        self.tree.column("timestamp", width=150)
        self.tree.column("src_ip", width=100)
        self.tree.column("src_port", width=60)
        self.tree.column("dest_ip", width=100)
        self.tree.column("dest_port", width=60)
        self.tree.column("category", width=150)
        self.tree.column("signature", width=300)
        self.tree.column("severity", width=40)

        # Scrollbar
        scrollbar = ttk.Scrollbar(alert_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)
        
        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # Configure Tags for Colors
        # Severity 1: High (Red)
        # Severity 2: Medium (Orange)
        # Severity 3: Low/Info (Green/Default)
        self.tree.tag_configure('high', background='#ffcccc')   # Light Red
        self.tree.tag_configure('medium', background='#ffebcc') # Light Orange
        self.tree.tag_configure('low', background='#e6ffcc')    # Light Green

        # --- Status Bar ---
        self.status_var = tk.StringVar(value="Ready")
        status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor="w")
        status_bar.pack(side="bottom", fill="x")

        # --- Console Log ---
        console_frame = ttk.LabelFrame(self.root, text="Suricata Log", padding="10")
        console_frame.pack(fill="x", padx=10, pady=5)
        
        self.console_text = scrolledtext.ScrolledText(console_frame, height=6, state='disabled')
        self.console_text.pack(fill="both", expand=True)

    def log(self, message):
        self.status_var.set(message)
        print(message)
        
        self.console_text.configure(state='normal')
        self.console_text.insert(tk.END, message + "\n")
        self.console_text.see(tk.END)
        self.console_text.configure(state='disabled')

    def start_ids(self):
        suricata_exe = self.suricata_path_var.get()
        config_file = self.config_path_var.get()
        interface = self.interface_var.get()
        log_dir = self.log_dir_var.get()
        
        if not os.path.exists(suricata_exe):
            messagebox.showerror("Error", f"Suricata executable not found at {suricata_exe}")
            return

        # Ensure log directory exists
        if not os.path.exists(log_dir):
            try:
                os.makedirs(log_dir)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to create log directory: {e}")
                return

        # Command to run Suricata
        # -c config -i interface -l log_dir
        # Added -k none to ignore checksum errors which are common on Windows
        cmd = [suricata_exe, "-c", config_file, "-i", interface, "-l", log_dir, "-k", "none"]
        
        try:
            # Start Suricata in a subprocess
            # We use creationflags=subprocess.CREATE_NO_WINDOW to hide the console window on Windows if desired,
            # but keeping it visible might be useful for debugging initially.
            self.suricata_process = subprocess.Popen(
                cmd, 
                cwd=os.path.dirname(suricata_exe),
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )
            
            self.is_running = True
            self.stop_event.clear()
            
            self.start_btn.config(state="disabled")
            self.stop_btn.config(state="normal")
            self.log(f"Suricata started on {interface}...")

            # Start Log Monitor Thread
            threading.Thread(target=self.monitor_logs, daemon=True).start()
            
            # Start Process Output Monitor Thread
            threading.Thread(target=self.monitor_process_output, daemon=True).start()

        except Exception as e:
            messagebox.showerror("Error", f"Failed to start Suricata: {e}")

    def allow_local_attacks(self):
        # This modifies suricata.yaml to treat ALL traffic as "External".
        # This allows standard rules (like SQL Injection) to trigger even if the attack
        # comes from your own local network (e.g. your phone or laptop).
        config_path = self.config_path_var.get()
        if not os.path.exists(config_path):
            messagebox.showerror("Error", f"Config file not found at {config_path}")
            return

        try:
            with open(config_path, 'r') as f:
                content = f.read()
            
            # Replace EXTERNAL_NET: "!$HOME_NET" with EXTERNAL_NET: "any"
            if 'EXTERNAL_NET: "!$HOME_NET"' in content:
                new_content = content.replace('EXTERNAL_NET: "!$HOME_NET"', 'EXTERNAL_NET: "any"')
                
                # Backup
                import shutil
                try:
                    shutil.copy(config_path, config_path + ".bak_net")
                except:
                    pass 

                with open(config_path, 'w') as f:
                    f.write(new_content)
                
                self.log("Configuration updated: EXTERNAL_NET set to 'any'.")
                messagebox.showinfo("Success", "Local attacks enabled!\nStandard rules will now trigger on local traffic.\nPlease Restart IDS.")
            else:
                if 'EXTERNAL_NET: "any"' in content:
                     messagebox.showinfo("Info", "Configuration already set to allow local attacks.")
                else:
                     messagebox.showwarning("Warning", "Could not find 'EXTERNAL_NET: \"!$HOME_NET\"' in config.\nYou may need to edit it manually.")

        except PermissionError:
            messagebox.showerror("Permission Denied", "Cannot write to config file.\nPlease run this application as Administrator.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to update config: {e}")

    def enable_test_rules(self):
        # Create a local.rules file with specific test rules that work on local networks
        local_rules_path = os.path.join(os.getcwd(), "local.rules")
        try:
            with open(local_rules_path, "w") as f:
                # Rule 1: Detect "ATTACK" keyword (Red Alert)
                f.write('alert http any any -> any any (msg:"TEST ATTACK DETECTED"; content:"ATTACK"; http_uri; classtype:web-application-attack; sid:1000005; rev:1;)\n')
                
                # Rule 2: Detect SQL Injection pattern explicitly for local network (Red Alert)
                f.write('alert http any any -> any any (msg:"LOCAL SQL INJECTION ATTEMPT"; content:"UNION"; http_uri; content:"SELECT"; http_uri; classtype:web-application-attack; sid:1000006; rev:1;)\n')
                
                # Rule 3: Detect Ping (Green/Info)
                f.write('alert icmp any any -> any any (msg:"ICMP Ping Detected"; sid:1000001; rev:1;)\n')
                
            self.log(f"Created local.rules with Test Attack rules.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to create local.rules: {e}")
            return

        # Now ensure suricata.yaml includes this file
        self.update_config_to_include_local_rules(local_rules_path)

    def update_config_to_include_local_rules(self, local_rules_path):
        config_path = self.config_path_var.get()
        if not os.path.exists(config_path):
            messagebox.showerror("Error", f"Config file not found at {config_path}")
            return

        try:
            with open(config_path, 'r') as f:
                lines = f.readlines()
            
            new_lines = []
            in_rule_files = False
            local_rule_added = False
            formatted_path = local_rules_path.replace("\\", "/")
            
            for line in lines:
                stripped = line.strip()
                if stripped.startswith("rule-files:"):
                    in_rule_files = True
                    new_lines.append(line)
                    continue
                
                if in_rule_files:
                    if stripped.startswith("-"):
                        if formatted_path in line:
                            local_rule_added = True
                        new_lines.append(line)
                    elif stripped == "" or stripped.startswith("#"):
                        new_lines.append(line)
                    else:
                        if not local_rule_added:
                            new_lines.insert(len(new_lines), f"  - {formatted_path}\n")
                            local_rule_added = True
                        in_rule_files = False
                        new_lines.append(line)
                else:
                    new_lines.append(line)
            
            if in_rule_files and not local_rule_added:
                 new_lines.append(f"  - {formatted_path}\n")

            with open(config_path, 'w') as f:
                f.writelines(new_lines)
                
            self.log("Configuration updated to include local.rules.")
            messagebox.showinfo("Success", "Test rules enabled!\n1. Restart IDS.\n2. Visit http://<IP>/ATTACK from your phone.")

        except Exception as e:
            messagebox.showerror("Error", f"Failed to update config: {e}")

    def enable_ping_rules(self):
        # Deprecated in favor of enable_test_rules, but keeping for compatibility if needed
        self.enable_test_rules()

    def fix_config(self):
        config_path = self.config_path_var.get()
        if not os.path.exists(config_path):
            messagebox.showerror("Error", f"Config file not found at {config_path}")
            return
        
        try:
            with open(config_path, 'r') as f:
                lines = f.readlines()
            
            new_lines = []
            in_rule_files = False
            rules_replaced = False
            
            for line in lines:
                stripped = line.strip()
                
                # Detect start of rule-files section
                if stripped.startswith("rule-files:"):
                    in_rule_files = True
                    new_lines.append(line)
                    # Add the single consolidated rule file
                    new_lines.append("  - suricata.rules\n")
                    rules_replaced = True
                    continue
                
                if in_rule_files:
                    # Check if we are still in the list (lines starting with -)
                    if stripped.startswith("-"):
                        # Comment out existing rules
                        new_lines.append("# " + line)
                    elif stripped == "" or stripped.startswith("#"):
                        # Keep empty lines and comments
                        new_lines.append(line)
                    else:
                        # We hit something that is not a list item, so we are out of the section
                        in_rule_files = False
                        new_lines.append(line)
                else:
                    new_lines.append(line)
            
            if not rules_replaced:
                 messagebox.showwarning("Warning", "Could not find 'rule-files:' section in config.")
                 return

            # Backup
            import shutil
            try:
                shutil.copy(config_path, config_path + ".bak")
            except PermissionError:
                 messagebox.showerror("Permission Denied", "Cannot backup config file.\nPlease run this application as Administrator.")
                 return

            with open(config_path, 'w') as f:
                f.writelines(new_lines)
                
            self.log("Configuration fixed. 'rule-files' now points to 'suricata.rules'.")
            messagebox.showinfo("Success", "Configuration updated!\nOriginal config backed up to .bak.\n\nPlease Restart IDS.")

        except PermissionError:
            messagebox.showerror("Permission Denied", "Cannot write to config file.\nPlease run this application as Administrator.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to fix config: {e}")

    def update_rules(self):
        self.log("Updating rules... This may take a minute.")
        # Try to run suricata-update
        # It is usually in the same folder as suricata.exe or in Scripts
        suricata_dir = os.path.dirname(self.suricata_path_var.get())
        # Common locations for suricata-update
        possible_paths = [
            os.path.join(suricata_dir, "suricata-update.exe"),
            os.path.join(suricata_dir, "..", "Scripts", "suricata-update.exe"),
            "suricata-update" # In PATH
        ]
        
        update_cmd = None
        for p in possible_paths:
            if p == "suricata-update":
                update_cmd = p
                break
            if os.path.exists(p):
                update_cmd = p
                break
        
        if not update_cmd:
            self.log("Could not find suricata-update.exe. Please run it manually.")
            messagebox.showwarning("Update Failed", "Could not find suricata-update.exe.\nPlease run 'suricata-update' in a terminal.")
            return

        def run_update():
            try:
                # We use creationflags to hide window
                creation_flags = 0x08000000 if os.name == 'nt' else 0
                process = subprocess.run(
                    [update_cmd], 
                    capture_output=True, 
                    text=True,
                    creationflags=creation_flags
                )
                if process.returncode == 0:
                    self.root.after(0, self.log, "Rules updated successfully.")
                    self.root.after(0, messagebox.showinfo, "Success", "Rules updated successfully.\nPlease restart the IDS.")
                else:
                    self.root.after(0, self.log, f"Rule update failed: {process.stderr}")
                    self.root.after(0, messagebox.showerror, "Error", f"Rule update failed:\n{process.stderr}\n\nTry running the application as Administrator.")
            except Exception as e:
                self.root.after(0, self.log, f"Rule update error: {e}")

        threading.Thread(target=run_update, daemon=True).start()

    def monitor_process_output(self):
        """Reads stdout and stderr from the Suricata process and logs it."""
        while self.is_running and self.suricata_process:
            # Read line by line
            output = self.suricata_process.stdout.readline()
            error = self.suricata_process.stderr.readline()
            
            if output:
                self.root.after(0, self.log, f"[SURICATA] {output.strip()}")
            if error:
                self.root.after(0, self.log, f"[SURICATA ERROR] {error.strip()}")
                
            if output == '' and error == '' and self.suricata_process.poll() is not None:
                break
                
        if self.is_running:
             self.root.after(0, self.log, "Suricata process ended unexpectedly.")
             self.root.after(0, self.stop_ids)

    def stop_ids(self):
        if self.suricata_process:
            self.suricata_process.terminate()
            self.suricata_process = None
        
        self.is_running = False
        self.stop_event.set()
        
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        self.log("Suricata stopped.")

    def list_interfaces(self):
        # On Windows, suricata --list-interfaces might not be available or reliable.
        # We will use ipconfig to let the user see their adapters and IP addresses.
        # They can use the IP address as the interface argument.
        try:
            if os.name == 'nt':
                cmd = ["ipconfig"]
                msg = "Look for your active adapter (e.g., Wi-Fi or Ethernet).\nYou can use the 'IPv4 Address' (e.g., 192.168.1.x) as the Interface."
            else:
                cmd = ["ip", "addr"]
                msg = "Look for your active interface name (e.g., eth0, wlan0)."

            creation_flags = 0x08000000 if os.name == 'nt' else 0
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                creationflags=creation_flags
            )
            
            if result.returncode == 0:
                self.show_interface_info(result.stdout, msg)
            else:
                messagebox.showerror("Error", f"Failed to list interfaces:\n{result.stderr}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to run command: {e}")

    def show_interface_info(self, content, help_msg):
        top = tk.Toplevel(self.root)
        top.title("Network Interfaces")
        top.geometry("600x500")
        
        lbl = ttk.Label(top, text=help_msg, padding=10)
        lbl.pack(fill="x")

        txt = scrolledtext.ScrolledText(top, wrap=tk.WORD)
        txt.pack(fill="both", expand=True, padx=10, pady=10)
        txt.insert(tk.END, content)
        txt.configure(state='disabled')

    def test_ids(self):
        # Trigger a test alert by accessing testmynids.org
        # This should trigger: GPL ATTACK_RESPONSE id check returned root
        try:
            import urllib.request
            url = "http://testmynids.org/uid/index.html"
            self.log(f"Sending test request to {url}...")
            
            # We need to make sure we actually read the response so the packet comes back
            with urllib.request.urlopen(url, timeout=10) as response:
                content = response.read()
                self.log("Test request sent. Waiting for alert...")
                messagebox.showinfo("Test Sent", "Test HTTP request sent.\nIf Suricata is working, you should see an alert shortly.")
        except Exception as e:
            self.log(f"Test failed: {e}")
            messagebox.showerror("Test Failed", f"Could not send test request: {e}")

    def monitor_logs(self):
        log_dir = self.log_dir_var.get()
        eve_path = os.path.join(log_dir, EVE_JSON_FILE)
        
        self.log(f"Waiting for logs at {eve_path}...")
        
        # Wait for file to exist
        while not os.path.exists(eve_path) and not self.stop_event.is_set():
            time.sleep(1)
        
        if self.stop_event.is_set():
            return

        self.log(f"Monitoring {eve_path}")

        # Tail the file
        with open(eve_path, 'r') as f:
            # Go to the end of the file
            f.seek(0, os.SEEK_END)
            
            while self.is_running and not self.stop_event.is_set():
                line = f.readline()
                if not line:
                    time.sleep(0.1)
                    continue
                
                try:
                    event = json.loads(line)
                    if event.get('event_type') == 'alert':
                        self.process_alert(event)
                except json.JSONDecodeError:
                    pass

    def process_alert(self, event):
        # Extract relevant fields
        timestamp = event.get('timestamp', '')
        src_ip = event.get('src_ip', '')
        src_port = event.get('src_port', '')
        dest_ip = event.get('dest_ip', '')
        dest_port = event.get('dest_port', '')
        
        alert = event.get('alert', {})
        signature = alert.get('signature', '')
        category = alert.get('category', '')
        severity = alert.get('severity', '')

        # Insert into Treeview (Thread-safe way)
        self.root.after(0, self.add_alert_to_ui, timestamp, src_ip, src_port, dest_ip, dest_port, category, signature, severity)

    def add_alert_to_ui(self, timestamp, src_ip, src_port, dest_ip, dest_port, category, signature, severity):
        # Determine tag based on severity
        tag = 'low'
        try:
            sev_int = int(severity)
            if sev_int == 1:
                tag = 'high'
            elif sev_int == 2:
                tag = 'medium'
            else:
                tag = 'low'
        except (ValueError, TypeError):
            pass

        self.tree.insert("", 0, values=(timestamp, src_ip, src_port, dest_ip, dest_port, category, signature, severity), tags=(tag,))
        
        # Keep only last 1000 alerts to prevent memory issues
        if len(self.tree.get_children()) > 1000:
            self.tree.delete(self.tree.get_children()[-1])

if __name__ == "__main__":
    root = tk.Tk()
    app = NetShieldIDS(root)
    root.mainloop()
