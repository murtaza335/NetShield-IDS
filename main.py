import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import subprocess
import threading
import time
import json
import os
import sys
from collections import defaultdict, deque
from datetime import datetime
import matplotlib
matplotlib.use('TkAgg')
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.pyplot as plt
from matplotlib.animation import FuncAnimation

# --- NEW IMPORTS FOR API ---
from flask import Flask, jsonify
from flask_cors import CORS
# ---------------------------

# Default Configuration for Windows
DEFAULT_SURICATA_PATH = r"C:\Program Files\Suricata\suricata.exe"
DEFAULT_CONFIG_PATH = r"C:\Program Files\Suricata\suricata.yaml"
DEFAULT_LOG_DIR = os.path.join(os.getcwd(), "logs")
EVE_JSON_FILE = "eve.json"

class NetShieldIDS:
    def __init__(self, root):
        self.root = root
        self.root.title("NetShield IDS - Intrusion Detection System")
        self.root.geometry("1400x800")
        self.root.configure(bg='#f0f0f0')
        
        self.is_running = False
        self.suricata_process = None
        self.stop_event = threading.Event()
        
        # Statistics tracking
        self.alert_stats = {
            'high': 0,
            'medium': 0,
            'low': 0,
            'total': 0
        }
        self.alerts_per_minute = deque(maxlen=60)
        self.category_stats = defaultdict(int)
        self.last_minute = datetime.now().minute
        self.current_minute_count = 0
        
        # --- NEW DATA STORE FOR API ---
        self.recent_alerts_list = deque(maxlen=100) # Stores last 100 alerts for mobile app
        self.start_api_server()
        # ------------------------------

        self.setup_ui()
        self.start_chart_updates()

    # ==========================
    # NEW: FLASK API SECTION
    # ==========================
    def start_api_server(self):
        """Starts a Flask server in a background thread."""
        app = Flask(__name__)
        CORS(app) # Allows mobile apps/web apps to connect without CORS issues

        @app.route('/api/stats', methods=['GET'])
        def get_stats():
            return jsonify({
                "stats": self.alert_stats,
                "alerts_per_minute": list(self.alerts_per_minute),
                "is_running": self.is_running,
                "timestamp": datetime.now().isoformat()
            })

        @app.route('/api/alerts', methods=['GET'])
        def get_alerts():
            return jsonify(list(self.recent_alerts_list))

        @app.route('/api/status', methods=['GET'])
        def get_status():
            return jsonify({
                "status": "online" if self.is_running else "offline",
                "interface": self.interface_var.get()
            })

        def run_flask():
            # host='0.0.0.0' makes it available on your local network
            # port 5000 is standard
            app.run(host='0.0.0.0', port=5000, debug=False, use_reloader=False)

        api_thread = threading.Thread(target=run_flask, daemon=True)
        api_thread.start()

    # ==========================
    # EXISTING UI LOGIC
    # ==========================
    def setup_ui(self):
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=5, pady=5)
        
        self.dashboard_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.dashboard_tab, text="  Dashboard  ")
        
        self.alerts_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.alerts_tab, text="  Alerts  ")
        
        self.config_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.config_tab, text="  Configuration  ")
        
        self.console_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.console_tab, text="  Console  ")
        
        self.setup_dashboard_tab()
        self.setup_alerts_tab()
        self.setup_config_tab()
        self.setup_console_tab()
        self.setup_status_bar()

    def setup_status_bar(self):
        status_frame = ttk.Frame(self.root)
        status_frame.pack(side="bottom", fill="x", padx=5, pady=2)
        self.status_var = tk.StringVar(value="● Ready | API: http://0.0.0.0:5000")
        self.status_label = ttk.Label(status_frame, textvariable=self.status_var, relief=tk.SUNKEN, anchor="w")
        self.status_label.pack(side="left", fill="x", expand=True)
        self.status_indicator = tk.Canvas(status_frame, width=20, height=20, highlightthickness=0)
        self.status_indicator.pack(side="right", padx=5)
        self.status_circle = self.status_indicator.create_oval(5, 5, 15, 15, fill='gray', outline='')

    def setup_dashboard_tab(self):
        stats_frame = ttk.Frame(self.dashboard_tab)
        stats_frame.pack(fill="x", padx=10, pady=10)
        self.create_stat_card(stats_frame, "Total Alerts", "total", 0, "#3498db")
        self.create_stat_card(stats_frame, "High Severity", "high", 1, "#e74c3c")
        self.create_stat_card(stats_frame, "Medium Severity", "medium", 2, "#f39c12")
        self.create_stat_card(stats_frame, "Low Severity", "low", 3, "#2ecc71")
        control_frame = ttk.LabelFrame(self.dashboard_tab, text="Controls", padding="10")
        control_frame.pack(fill="x", padx=10, pady=5)
        btn_container = ttk.Frame(control_frame)
        btn_container.pack()
        self.start_btn = ttk.Button(btn_container, text="▶ Start IDS", command=self.start_ids, width=15)
        self.start_btn.grid(row=0, column=0, padx=5, pady=5)
        self.stop_btn = ttk.Button(btn_container, text="■ Stop IDS", command=self.stop_ids, state="disabled", width=15)
        self.stop_btn.grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(btn_container, text="🔄 Test IDS", command=self.test_ids, width=15).grid(row=0, column=2, padx=5, pady=5)
        ttk.Button(btn_container, text="🌐 Interfaces", command=self.list_interfaces, width=15).grid(row=0, column=3, padx=5, pady=5)
        charts_frame = ttk.Frame(self.dashboard_tab)
        charts_frame.pack(fill="both", expand=True, padx=10, pady=5)
        left_chart_frame = ttk.LabelFrame(charts_frame, text="Severity Distribution", padding="5")
        left_chart_frame.pack(side="left", fill="both", expand=True, padx=5)
        self.severity_fig = Figure(figsize=(5, 4), dpi=80, facecolor='#f0f0f0')
        self.severity_ax = self.severity_fig.add_subplot(111)
        self.severity_canvas = FigureCanvasTkAgg(self.severity_fig, left_chart_frame)
        self.severity_canvas.get_tk_widget().pack(fill="both", expand=True)
        self.update_severity_chart()
        right_chart_frame = ttk.LabelFrame(charts_frame, text="Alerts Timeline (Last 60 Minutes)", padding="5")
        right_chart_frame.pack(side="right", fill="both", expand=True, padx=5)
        self.timeline_fig = Figure(figsize=(5, 4), dpi=80, facecolor='#f0f0f0')
        self.timeline_ax = self.timeline_fig.add_subplot(111)
        self.timeline_canvas = FigureCanvasTkAgg(self.timeline_fig, right_chart_frame)
        self.timeline_canvas.get_tk_widget().pack(fill="both", expand=True)
        self.update_timeline_chart()

    def create_stat_card(self, parent, label, stat_key, column, color):
        card = ttk.Frame(parent, relief=tk.RIDGE, borderwidth=2)
        card.pack(side="left", fill="both", expand=True, padx=5)
        header = tk.Canvas(card, height=5, bg=color, highlightthickness=0)
        header.pack(fill="x")
        value_var = tk.StringVar(value="0")
        setattr(self, f"{stat_key}_var", value_var)
        value_label = ttk.Label(card, textvariable=value_var, font=("Segoe UI", 24, "bold"))
        value_label.pack(pady=(10, 0))
        ttk.Label(card, text=label, font=("Segoe UI", 10)).pack(pady=(0, 10))

    def setup_alerts_tab(self):
        filter_frame = ttk.Frame(self.alerts_tab)
        filter_frame.pack(fill="x", padx=10, pady=5)
        ttk.Label(filter_frame, text="Filter:").pack(side="left", padx=5)
        self.filter_var = tk.StringVar(value="all")
        ttk.Radiobutton(filter_frame, text="All", variable=self.filter_var, value="all").pack(side="left", padx=5)
        ttk.Radiobutton(filter_frame, text="High", variable=self.filter_var, value="high").pack(side="left", padx=5)
        ttk.Radiobutton(filter_frame, text="Medium", variable=self.filter_var, value="medium").pack(side="left", padx=5)
        ttk.Radiobutton(filter_frame, text="Low", variable=self.filter_var, value="low").pack(side="left", padx=5)
        ttk.Button(filter_frame, text="Clear All", command=self.clear_alerts).pack(side="right", padx=5)
        table_frame = ttk.Frame(self.alerts_tab)
        table_frame.pack(fill="both", expand=True, padx=10, pady=5)
        columns = ("timestamp", "severity", "src_ip", "src_port", "dest_ip", "dest_port", "category", "signature")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings", height=20)
        self.tree.heading("timestamp", text="Timestamp")
        self.tree.heading("severity", text="Severity")
        self.tree.heading("src_ip", text="Source IP")
        self.tree.heading("src_port", text="Port")
        self.tree.heading("dest_ip", text="Destination IP")
        self.tree.heading("dest_port", text="Port")
        self.tree.heading("category", text="Category")
        self.tree.heading("signature", text="Signature")
        self.tree.column("timestamp", width=150)
        self.tree.column("severity", width=80)
        self.tree.column("src_ip", width=120)
        self.tree.column("src_port", width=60)
        self.tree.column("dest_ip", width=120)
        self.tree.column("dest_port", width=60)
        self.tree.column("category", width=180)
        self.tree.column("signature", width=350)
        vsb = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=self.tree.yview)
        hsb = ttk.Scrollbar(table_frame, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        table_frame.grid_rowconfigure(0, weight=1)
        table_frame.grid_columnconfigure(0, weight=1)
        self.tree.tag_configure('high', background='#ffcccc', foreground='#000')
        self.tree.tag_configure('medium', background='#ffe6cc', foreground='#000')
        self.tree.tag_configure('low', background='#e6ffe6', foreground='#000')

    def setup_config_tab(self):
        config_frame = ttk.LabelFrame(self.config_tab, text="Suricata Configuration", padding="15")
        config_frame.pack(fill="both", expand=True, padx=10, pady=10)
        ttk.Label(config_frame, text="Suricata Executable Path:", font=("Segoe UI", 9, "bold")).grid(row=0, column=0, sticky="w", pady=5)
        self.suricata_path_var = tk.StringVar(value=DEFAULT_SURICATA_PATH)
        ttk.Entry(config_frame, textvariable=self.suricata_path_var, width=70).grid(row=0, column=1, padx=10, pady=5, sticky="ew")
        ttk.Label(config_frame, text="Configuration File Path:", font=("Segoe UI", 9, "bold")).grid(row=1, column=0, sticky="w", pady=5)
        self.config_path_var = tk.StringVar(value=DEFAULT_CONFIG_PATH)
        ttk.Entry(config_frame, textvariable=self.config_path_var, width=70).grid(row=1, column=1, padx=10, pady=5, sticky="ew")
        ttk.Label(config_frame, text="Network Interface:", font=("Segoe UI", 9, "bold")).grid(row=2, column=0, sticky="w", pady=5)
        self.interface_var = tk.StringVar(value="Ethernet")
        ttk.Entry(config_frame, textvariable=self.interface_var, width=30).grid(row=2, column=1, sticky="w", padx=10, pady=5)
        ttk.Label(config_frame, text="Log Directory:", font=("Segoe UI", 9, "bold")).grid(row=3, column=0, sticky="w", pady=5)
        self.log_dir_var = tk.StringVar(value=DEFAULT_LOG_DIR)
        ttk.Entry(config_frame, textvariable=self.log_dir_var, width=70).grid(row=3, column=1, padx=10, pady=5, sticky="ew")
        config_frame.columnconfigure(1, weight=1)
        advanced_frame = ttk.LabelFrame(self.config_tab, text="Advanced Options", padding="15")
        advanced_frame.pack(fill="x", padx=10, pady=10)
        btn_grid = ttk.Frame(advanced_frame)
        btn_grid.pack()
        ttk.Button(btn_grid, text="Update Rules", command=self.update_rules, width=20).grid(row=0, column=0, padx=5, pady=5)
        ttk.Button(btn_grid, text="Fix Configuration", command=self.fix_config, width=20).grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(btn_grid, text="Allow Local Attacks", command=self.allow_local_attacks, width=20).grid(row=0, column=2, padx=5, pady=5)

    def setup_console_tab(self):
        console_frame = ttk.Frame(self.console_tab)
        console_frame.pack(fill="both", expand=True, padx=10, pady=10)
        ttk.Label(console_frame, text="Suricata Process Output", font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=5)
        self.console_text = scrolledtext.ScrolledText(console_frame, height=25, state='disabled', font=("Consolas", 9), bg="#1e1e1e", fg="#d4d4d4")
        self.console_text.pack(fill="both", expand=True)

    def clear_alerts(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.alert_stats = {'high': 0, 'medium': 0, 'low': 0, 'total': 0}
        self.category_stats.clear()
        self.alerts_per_minute.clear()
        self.recent_alerts_list.clear() # Clear API list too
        self.update_stat_displays()
        self.update_severity_chart()
        self.update_timeline_chart()

    def update_stat_displays(self):
        self.total_var.set(str(self.alert_stats['total']))
        self.high_var.set(str(self.alert_stats['high']))
        self.medium_var.set(str(self.alert_stats['medium']))
        self.low_var.set(str(self.alert_stats['low']))

    def update_severity_chart(self):
        self.severity_ax.clear()
        sizes = [self.alert_stats['high'], self.alert_stats['medium'], self.alert_stats['low']]
        labels = ['High', 'Medium', 'Low']
        colors = ['#e74c3c', '#f39c12', '#2ecc71']
        if sum(sizes) == 0:
            sizes = [1, 1, 1]
            self.severity_ax.text(0.5, 0.5, 'No Alerts Yet', horizontalalignment='center', verticalalignment='center', transform=self.severity_ax.transAxes, fontsize=12)
            self.severity_ax.pie(sizes, colors=['#cccccc']*3, startangle=90)
        else:
            explode = (0.05, 0.05, 0.05)
            self.severity_ax.pie(sizes, explode=explode, labels=labels, colors=colors, autopct='%1.1f%%', startangle=90, textprops={'fontsize': 9})
        self.severity_ax.axis('equal')
        self.severity_canvas.draw()

    def update_timeline_chart(self):
        self.timeline_ax.clear()
        if len(self.alerts_per_minute) == 0:
            self.timeline_ax.text(0.5, 0.5, 'No Alert Data Yet', horizontalalignment='center', verticalalignment='center', transform=self.timeline_ax.transAxes, fontsize=12)
            self.timeline_ax.set_xlim(0, 60)
            self.timeline_ax.set_ylim(0, 10)
        else:
            x = list(range(len(self.alerts_per_minute)))
            y = list(self.alerts_per_minute)
            self.timeline_ax.plot(x, y, color='#3498db', linewidth=2, marker='o', markersize=4)
            self.timeline_ax.fill_between(x, y, alpha=0.3, color='#3498db')
            self.timeline_ax.set_xlabel('Minutes Ago', fontsize=9)
            self.timeline_ax.set_ylabel('Alerts', fontsize=9)
            self.timeline_ax.grid(True, alpha=0.3)
        self.timeline_canvas.draw()

    def start_chart_updates(self):
        def update_charts():
            if self.is_running:
                current_minute = datetime.now().minute
                if current_minute != self.last_minute:
                    self.alerts_per_minute.append(self.current_minute_count)
                    self.current_minute_count = 0
                    self.last_minute = current_minute
                    self.update_timeline_chart()
            self.root.after(5000, update_charts)
        update_charts()

    def log(self, message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted_msg = f"[{timestamp}] {message}"
        self.status_var.set(f"● {message} | API: 5000")
        self.console_text.configure(state='normal')
        self.console_text.insert(tk.END, formatted_msg + "\n")
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
        if not os.path.exists(log_dir):
            try: os.makedirs(log_dir)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to create log directory: {e}")
                return
        cmd = [suricata_exe, "-c", config_file, "-i", interface, "-l", log_dir, "-k", "none"]
        try:
            self.suricata_process = subprocess.Popen(cmd, cwd=os.path.dirname(suricata_exe), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
            self.is_running = True
            self.stop_event.clear()
            self.start_btn.config(state="disabled")
            self.stop_btn.config(state="normal")
            self.status_indicator.itemconfig(self.status_circle, fill='#2ecc71')
            self.log(f"Suricata started on interface {interface}")
            threading.Thread(target=self.monitor_logs, daemon=True).start()
            threading.Thread(target=self.monitor_process_output, daemon=True).start()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start Suricata: {e}")

    def allow_local_attacks(self):
        config_path = self.config_path_var.get()
        if not os.path.exists(config_path):
            messagebox.showerror("Error", f"Config file not found at {config_path}")
            return
        try:
            with open(config_path, 'r') as f:
                content = f.read()
            if 'EXTERNAL_NET: "!$HOME_NET"' in content:
                new_content = content.replace('EXTERNAL_NET: "!$HOME_NET"', 'EXTERNAL_NET: "any"')
                import shutil
                try: shutil.copy(config_path, config_path + ".bak_net")
                except: pass 
                with open(config_path, 'w') as f: f.write(new_content)
                self.log("Configuration updated: EXTERNAL_NET set to 'any'.")
                messagebox.showinfo("Success", "Local attacks enabled! Please Restart IDS.")
            else:
                if 'EXTERNAL_NET: "any"' in content: messagebox.showinfo("Info", "Already set.")
                else: messagebox.showwarning("Warning", "Manual edit needed.")
        except Exception as e: messagebox.showerror("Error", f"Failed: {e}")

    def enable_test_rules(self):
        local_rules_path = os.path.join(os.getcwd(), "local.rules")
        try:
            with open(local_rules_path, "w") as f:
                f.write('alert http any any -> any any (msg:"TEST ATTACK DETECTED"; content:"ATTACK"; http_uri; classtype:web-application-attack; sid:1000005; rev:1;)\n')
                f.write('alert http any any -> any any (msg:"LOCAL SQL INJECTION ATTEMPT"; content:"UNION"; http_uri; content:"SELECT"; http_uri; classtype:web-application-attack; sid:1000006; rev:1;)\n')
                f.write('alert icmp any any -> any any (msg:"ICMP Ping Detected"; sid:1000001; rev:1;)\n')
            self.log(f"Created local.rules.")
        except Exception as e: messagebox.showerror("Error", f"Failed: {e}")
        self.update_config_to_include_local_rules(local_rules_path)

    def update_config_to_include_local_rules(self, local_rules_path):
        config_path = self.config_path_var.get()
        if not os.path.exists(config_path): return
        try:
            with open(config_path, 'r') as f: lines = f.readlines()
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
                        if formatted_path in line: local_rule_added = True
                        new_lines.append(line)
                    elif stripped == "" or stripped.startswith("#"): new_lines.append(line)
                    else:
                        if not local_rule_added:
                            new_lines.insert(len(new_lines), f"  - {formatted_path}\n")
                            local_rule_added = True
                        in_rule_files = False
                        new_lines.append(line)
                else: new_lines.append(line)
            with open(config_path, 'w') as f: f.writelines(new_lines)
            self.log("Configuration updated.")
        except Exception as e: messagebox.showerror("Error", f"Failed: {e}")

    def fix_config(self):
        config_path = self.config_path_var.get()
        if not os.path.exists(config_path): return
        try:
            with open(config_path, 'r') as f: lines = f.readlines()
            new_lines = []; in_rule_files = False; rules_replaced = False
            for line in lines:
                stripped = line.strip()
                if stripped.startswith("rule-files:"):
                    in_rule_files = True; new_lines.append(line); new_lines.append("  - suricata.rules\n"); rules_replaced = True; continue
                if in_rule_files:
                    if stripped.startswith("-"): new_lines.append("# " + line)
                    elif stripped == "" or stripped.startswith("#"): new_lines.append(line)
                    else: in_rule_files = False; new_lines.append(line)
                else: new_lines.append(line)
            with open(config_path, 'w') as f: f.writelines(new_lines)
            self.log("Configuration fixed.")
        except Exception as e: messagebox.showerror("Error", str(e))

    def update_rules(self):
        self.log("Updating rules...")
        suricata_dir = os.path.dirname(self.suricata_path_var.get())
        update_cmd = "suricata-update"
        def run_update():
            try:
                process = subprocess.run([update_cmd], capture_output=True, text=True)
                if process.returncode == 0: self.root.after(0, self.log, "Rules updated.")
                else: self.root.after(0, self.log, "Update failed.")
            except: self.root.after(0, self.log, "Update error.")
        threading.Thread(target=run_update, daemon=True).start()

    def monitor_process_output(self):
        while self.is_running and self.suricata_process:
            output = self.suricata_process.stdout.readline()
            error = self.suricata_process.stderr.readline()
            if output: self.root.after(0, self.log, f"[SURICATA] {output.strip()}")
            if error: self.root.after(0, self.log, f"[SURICATA ERROR] {error.strip()}")
            if output == '' and error == '' and self.suricata_process.poll() is not None: break
        if self.is_running:
             self.root.after(0, self.log, "Process ended.")
             self.root.after(0, self.stop_ids)

    def stop_ids(self):
        if self.suricata_process: self.suricata_process.terminate()
        self.suricata_process = None
        self.is_running = False
        self.stop_event.set()
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        self.status_indicator.itemconfig(self.status_circle, fill='gray')
        self.log("Suricata stopped")

    def list_interfaces(self):
        try:
            cmd = ["ipconfig"] if os.name == 'nt' else ["ip", "addr"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            self.show_interface_info(result.stdout, "Check your IP address.")
        except Exception as e: messagebox.showerror("Error", str(e))

    def show_interface_info(self, content, help_msg):
        top = tk.Toplevel(self.root)
        txt = scrolledtext.ScrolledText(top, wrap=tk.WORD)
        txt.pack(fill="both", expand=True)
        txt.insert(tk.END, content)

    def test_ids(self):
        try:
            import urllib.request
            url = "http://testmynids.org/uid/index.html"
            with urllib.request.urlopen(url, timeout=10) as response:
                response.read()
                self.log("Test sent.")
        except Exception as e: self.log(f"Test failed: {e}")

    def monitor_logs(self):
        log_dir = self.log_dir_var.get()
        eve_path = os.path.join(log_dir, EVE_JSON_FILE)
        while not os.path.exists(eve_path) and not self.stop_event.is_set(): time.sleep(1)
        if self.stop_event.is_set(): return
        with open(eve_path, 'r') as f:
            f.seek(0, os.SEEK_END)
            while self.is_running and not self.stop_event.is_set():
                line = f.readline()
                if not line: time.sleep(0.1); continue
                try:
                    event = json.loads(line)
                    if event.get('event_type') == 'alert': self.process_alert(event)
                except: pass

    def process_alert(self, event):
        alert_data = {
            'timestamp': event.get('timestamp', ''),
            'src_ip': event.get('src_ip', ''),
            'src_port': event.get('src_port', ''),
            'dest_ip': event.get('dest_ip', ''),
            'dest_port': event.get('dest_port', ''),
            'signature': event.get('alert', {}).get('signature', ''),
            'category': event.get('alert', {}).get('category', ''),
            'severity': event.get('alert', {}).get('severity', '')
        }
        
        # Add to API list
        self.recent_alerts_list.appendleft(alert_data)
        
        # UI Update
        self.root.after(0, self.add_alert_to_ui, 
                        alert_data['timestamp'], alert_data['src_ip'], alert_data['src_port'], 
                        alert_data['dest_ip'], alert_data['dest_port'], 
                        alert_data['category'], alert_data['signature'], alert_data['severity'])

    def add_alert_to_ui(self, timestamp, src_ip, src_port, dest_ip, dest_port, category, signature, severity):
        tag = 'low'
        try:
            sev_int = int(severity)
            if sev_int == 1: tag = 'high'; self.alert_stats['high'] += 1
            elif sev_int == 2: tag = 'medium'; self.alert_stats['medium'] += 1
            else: tag = 'low'; self.alert_stats['low'] += 1
        except: tag = 'low'; self.alert_stats['low'] += 1
        
        self.alert_stats['total'] += 1
        self.current_minute_count += 1
        if category: self.category_stats[category] += 1
        
        try:
            dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            display_time = dt.strftime("%Y-%m-%d %H:%M:%S")
        except: display_time = timestamp

        self.tree.insert("", 0, values=(display_time, tag.upper(), src_ip, src_port, dest_ip, dest_port, category, signature), tags=(tag,))
        if len(self.tree.get_children()) > 1000: self.tree.delete(self.tree.get_children()[-1])
        self.update_stat_displays()
        self.update_severity_chart()

if __name__ == "__main__":
    # Ensure dependencies are installed for the user
    # try: import flask, flask_cors
    # except ImportError: os.system('pip install flask flask-cors')
    
    root = tk.Tk()
    app = NetShieldIDS(root)
    root.mainloop()