# NetShield IDS with FastAPI Mobile Backend + Remote Access
# Install: pip install fastapi uvicorn websockets pyngrok
# For remote access: pip install pyngrok (creates secure tunnel)

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import subprocess, threading, time, json, os, socket, shutil
from collections import defaultdict, deque
from datetime import datetime
import matplotlib
matplotlib.use('TkAgg')
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from fastapi import FastAPI, WebSocket, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import uvicorn, asyncio
from typing import List, Dict, Optional

# Ngrok for remote access (optional)
try:
    from pyngrok import ngrok
    NGROK_AVAILABLE = True
except ImportError:
    NGROK_AVAILABLE = False

DEFAULT_SURICATA_PATH = r"C:\Program Files\Suricata\suricata.exe"
DEFAULT_CONFIG_PATH = r"C:\Program Files\Suricata\suricata.yaml"
DEFAULT_LOG_DIR = os.path.join(os.getcwd(), "logs")
EVE_JSON_FILE = "eve.json"

api_app = FastAPI(title="NetShield IDS API", version="2.0")
api_app.add_middleware(
    CORSMiddleware, 
    allow_origins=["*"], 
    allow_credentials=True, 
    allow_methods=["*"], 
    allow_headers=["*"]
)

class DataStore:
    def __init__(self):
        self.alerts = deque(maxlen=1000)
        self.websocket_clients = []
        self.lock = threading.Lock()
        self.alert_stats = {'high': 0, 'medium': 0, 'low': 0, 'total': 0}
        self.alerts_per_minute = deque(maxlen=60)
        self.category_stats = defaultdict(int)
        self.is_running = False
        self.status_message = "Ready"
        self.interface_name = ""
        self.start_time = None
        self.ngrok_url = None
        self.ngrok_tunnel = None
    
    def add_alert(self, alert_data):
        with self.lock:
            self.alerts.appendleft(alert_data)
            sev = alert_data.get('severity_tag', 'low')
            if sev in ['high','medium','low']: 
                self.alert_stats[sev] += 1
            else: 
                self.alert_stats['low'] += 1
            self.alert_stats['total'] += 1
            if cat := alert_data.get('category'): 
                self.category_stats[cat] += 1
    
    def get_dashboard_data(self):
        with self.lock:
            uptime = None
            if self.start_time:
                uptime = int((datetime.now() - self.start_time).total_seconds())
            
            return {
                'stats': self.alert_stats.copy(), 
                'alerts_timeline': list(self.alerts_per_minute),
                'category_stats': dict(self.category_stats), 
                'is_running': self.is_running,
                'status': self.status_message,
                'interface': self.interface_name,
                'uptime_seconds': uptime,
                'timestamp': datetime.now().isoformat(),
                'ngrok_url': self.ngrok_url
            }
    
    def get_recent_alerts(self, limit=100):
        with self.lock: 
            return list(self.alerts)[:limit]
    
    def update_minute_stats(self, count):
        with self.lock: 
            self.alerts_per_minute.append(count)
    
    def clear_data(self):
        with self.lock:
            self.alerts.clear()
            self.alerts_per_minute.clear()
            self.category_stats.clear()
            self.alert_stats = {'high': 0, 'medium': 0, 'low': 0, 'total': 0}

data_store = DataStore()

async def broadcast_to_clients(message):
    """Send message to all connected WebSocket clients"""
    dead = []
    for client in data_store.websocket_clients:
        try: 
            await client.send_json(message)
        except: 
            dead.append(client)
    for client in dead:
        if client in data_store.websocket_clients: 
            data_store.websocket_clients.remove(client)

# API Endpoints
@api_app.get("/")
async def root():
    return {
        "message": "NetShield IDS API v2.0", 
        "status": "online",
        "endpoints": {
            "dashboard": "/api/dashboard",
            "alerts": "/api/alerts?limit=100&severity=high",
            "stats": "/api/stats",
            "system": "/api/system",
            "clear": "/api/clear (POST)",
            "websocket": "/ws"
        },
        "websocket_clients": len(data_store.websocket_clients)
    }

@api_app.get("/api/dashboard")
async def get_dashboard():
    """Get complete dashboard data"""
    return data_store.get_dashboard_data()

@api_app.get("/api/alerts")
async def get_alerts(limit: int = 100, severity: Optional[str] = None, offset: int = 0):
    """Get alerts with optional filtering and pagination"""
    alerts = data_store.get_recent_alerts(limit + offset)
    
    if severity and severity.lower() in ['high', 'medium', 'low']:
        alerts = [a for a in alerts if a.get('severity_tag') == severity.lower()]
    
    # Apply pagination
    alerts = alerts[offset:offset + limit]
    
    return {
        "alerts": alerts, 
        "total": len(alerts),
        "offset": offset,
        "limit": limit
    }

@api_app.get("/api/stats")
async def get_stats():
    """Get statistics only"""
    return {
        "stats": data_store.alert_stats, 
        "category_stats": dict(data_store.category_stats), 
        "alerts_timeline": list(data_store.alerts_per_minute),
        "timestamp": datetime.now().isoformat()
    }

@api_app.get("/api/system")
async def get_system_info():
    """Get system information"""
    uptime = None
    if data_store.start_time:
        uptime = int((datetime.now() - data_store.start_time).total_seconds())
    
    return {
        "is_running": data_store.is_running,
        "status": data_store.status_message,
        "interface": data_store.interface_name,
        "uptime_seconds": uptime,
        "connected_clients": len(data_store.websocket_clients),
        "ngrok_url": data_store.ngrok_url,
        "timestamp": datetime.now().isoformat()
    }

@api_app.post("/api/clear")
async def clear_alerts():
    """Clear all alerts and statistics"""
    data_store.clear_data()
    await broadcast_to_clients({"type": "clear", "timestamp": datetime.now().isoformat()})
    return {"message": "All alerts cleared", "timestamp": datetime.now().isoformat()}

@api_app.get("/api/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "is_running": data_store.is_running,
        "timestamp": datetime.now().isoformat()
    }

@api_app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time updates"""
    await websocket.accept()
    data_store.websocket_clients.append(websocket)
    
    try:
        # Send initial data
        await websocket.send_json({
            "type": "initial", 
            "data": data_store.get_dashboard_data()
        })
        
        # Keep connection alive with ping/pong
        while True:
            try:
                data = await asyncio.wait_for(websocket.receive_text(), timeout=30.0)
                if data == "ping":
                    await websocket.send_text("pong")
            except asyncio.TimeoutError:
                # Send keepalive
                await websocket.send_json({
                    "type": "keepalive",
                    "timestamp": datetime.now().isoformat()
                })
    except Exception as e:
        print(f"WebSocket error: {e}")
    finally:
        if websocket in data_store.websocket_clients:
            data_store.websocket_clients.remove(websocket)

def get_local_ip():
    """Get local IP address"""
    try: 
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except: 
        return "127.0.0.1"

class NetShieldIDS:
    def __init__(self, root):
        self.root = root
        self.root.title("NetShield IDS with Remote API Access")
        self.root.geometry("1400x850")
        
        self.is_running = False
        self.suricata_process = None
        self.stop_event = threading.Event()
        self.alert_stats = {'high': 0, 'medium': 0, 'low': 0, 'total': 0}
        self.alerts_per_minute = deque(maxlen=60)
        self.category_stats = defaultdict(int)
        self.last_minute = datetime.now().minute
        self.current_minute_count = 0
        self.api_port = 8000
        self.ngrok_enabled = False
        
        self.setup_ui()
        self.start_chart_updates()
        self.start_api_server()

    def start_api_server(self):
        """Start FastAPI server in background thread"""
        def run_server():
            uvicorn.run(
                api_app, 
                host="0.0.0.0", 
                port=self.api_port, 
                log_level="warning"
            )
        
        threading.Thread(target=run_server, daemon=True).start()
        ip = get_local_ip()
        self.log(f"📱 Local API: http://{ip}:{self.api_port}")
        self.log(f"📱 WebSocket: ws://{ip}:{self.api_port}/ws")

    def setup_ui(self):
        nb = ttk.Notebook(self.root)
        nb.pack(fill="both", expand=True, padx=5, pady=5)
        
        self.dashboard_tab = ttk.Frame(nb)
        self.alerts_tab = ttk.Frame(nb)
        self.config_tab = ttk.Frame(nb)
        self.console_tab = ttk.Frame(nb)
        self.api_tab = ttk.Frame(nb)
        
        nb.add(self.dashboard_tab, text="  Dashboard  ")
        nb.add(self.alerts_tab, text="  Alerts  ")
        nb.add(self.config_tab, text="  Config  ")
        nb.add(self.console_tab, text="  Console  ")
        nb.add(self.api_tab, text="  📱 API & Remote  ")
        
        self.setup_dashboard_tab()
        self.setup_alerts_tab()
        self.setup_config_tab()
        self.setup_console_tab()
        self.setup_api_tab()
        self.setup_status_bar()

    def setup_api_tab(self):
        """Enhanced API tab with remote access options"""
        main_frame = ttk.Frame(self.api_tab)
        main_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Local Access Section
        local_frame = ttk.LabelFrame(main_frame, text="Local Network Access", padding="15")
        local_frame.pack(fill="x", pady=(0, 10))
        
        ip = get_local_ip()
        local_info = f"""Connect from devices on the same WiFi/LAN:

API Base URL: http://{ip}:{self.api_port}
WebSocket URL: ws://{ip}:{self.api_port}/ws

Available Endpoints:
  • GET  /api/dashboard    - Full dashboard data
  • GET  /api/alerts       - Get alerts (params: limit, severity, offset)
  • GET  /api/stats        - Statistics only
  • GET  /api/system       - System status and uptime
  • POST /api/clear        - Clear all alerts
  • GET  /api/health       - Health check
  • WS   /ws               - Real-time updates via WebSocket
"""
        
        local_text = tk.Text(local_frame, wrap=tk.WORD, font=("Consolas", 9), height=12)
        local_text.pack(fill="both", expand=True, padx=5, pady=5)
        local_text.insert(tk.END, local_info)
        local_text.configure(state='disabled')
        
        local_btn_frame = ttk.Frame(local_frame)
        local_btn_frame.pack(pady=5)
        ttk.Button(local_btn_frame, text="📋 Copy Local URL", 
                  command=lambda: self.copy(f"http://{ip}:{self.api_port}")).pack(side="left", padx=5)
        ttk.Button(local_btn_frame, text="🧪 Test API", 
                  command=self.test_api).pack(side="left", padx=5)
        
        # Remote Access Section
        remote_frame = ttk.LabelFrame(main_frame, text="Remote Access (Internet)", padding="15")
        remote_frame.pack(fill="both", expand=True)
        
        if NGROK_AVAILABLE:
            remote_info = """Enable remote access via Ngrok tunnel (access from anywhere):

1. Click 'Start Ngrok Tunnel' below
2. Copy the public URL provided
3. Use this URL from any device with internet access

Note: Free ngrok has limitations (connection time, bandwidth)
For production, consider: port forwarding, VPN, or cloud hosting
"""
        else:
            remote_info = """Remote Access Options:

OPTION 1: Install ngrok (Easiest)
  pip install pyngrok
  Then restart this application

OPTION 2: Port Forwarding (Router)
  1. Login to your router admin panel
  2. Forward port 8000 to this computer's IP
  3. Use your public IP: http://YOUR_PUBLIC_IP:8000
  4. Find public IP: https://whatismyipaddress.com

OPTION 3: VPN (Most Secure)
  • Setup WireGuard, Tailscale, or similar
  • Access via VPN network

OPTION 4: Cloud Deployment
  • Deploy to AWS, Azure, DigitalOcean
  • Run this app on cloud server
"""
        
        remote_text = scrolledtext.ScrolledText(remote_frame, wrap=tk.WORD, font=("Consolas", 9))
        remote_text.pack(fill="both", expand=True, padx=5, pady=5)
        remote_text.insert(tk.END, remote_info)
        remote_text.configure(state='disabled')
        
        # Ngrok controls
        if NGROK_AVAILABLE:
            ngrok_frame = ttk.Frame(remote_frame)
            ngrok_frame.pack(pady=10)
            
            self.ngrok_status_var = tk.StringVar(value="Not Started")
            ttk.Label(ngrok_frame, text="Ngrok Status:").pack(side="left", padx=5)
            ttk.Label(ngrok_frame, textvariable=self.ngrok_status_var, 
                     font=("Segoe UI", 9, "bold")).pack(side="left", padx=5)
            
            self.ngrok_btn = ttk.Button(ngrok_frame, text="🌐 Start Ngrok Tunnel", 
                                       command=self.toggle_ngrok)
            self.ngrok_btn.pack(side="left", padx=10)
            
            self.ngrok_url_var = tk.StringVar(value="")
            self.ngrok_url_entry = ttk.Entry(remote_frame, textvariable=self.ngrok_url_var, 
                                            state='readonly', font=("Consolas", 9))
            self.ngrok_url_entry.pack(fill="x", padx=5, pady=5)
            
            ttk.Button(remote_frame, text="📋 Copy Ngrok URL", 
                      command=lambda: self.copy(self.ngrok_url_var.get())).pack(pady=5)
        
        # Usage Example
        example_frame = ttk.LabelFrame(main_frame, text="Mobile App Example (JavaScript)", padding="15")
        example_frame.pack(fill="x", pady=(10, 0))
        
        example_code = f"""// React Native / JavaScript Example
const API_URL = 'http://{ip}:{self.api_port}';
const WS_URL = 'ws://{ip}:{self.api_port}/ws';

// Fetch dashboard data
fetch(`${{API_URL}}/api/dashboard`)
  .then(res => res.json())
  .then(data => console.log(data));

// WebSocket for live updates
const ws = new WebSocket(WS_URL);
ws.onmessage = (event) => {{
  const data = JSON.parse(event.data);
  if (data.type === 'new_alert') {{
    // Update UI with new alert
    console.log('New alert:', data.alert);
  }}
}};

// Send keepalive ping every 25 seconds
setInterval(() => ws.send('ping'), 25000);
"""
        
        example_text = scrolledtext.ScrolledText(example_frame, wrap=tk.WORD, 
                                                 font=("Consolas", 8), height=12)
        example_text.pack(fill="both", expand=True)
        example_text.insert(tk.END, example_code)
        example_text.configure(state='disabled')

    def toggle_ngrok(self):
        """Start or stop ngrok tunnel"""
        if not self.ngrok_enabled:
            self.start_ngrok()
        else:
            self.stop_ngrok()

    def start_ngrok(self):
        """Start ngrok tunnel for remote access"""
        try:
            # Start ngrok tunnel
            public_url = ngrok.connect(self.api_port, "http")
            data_store.ngrok_url = public_url.public_url
            data_store.ngrok_tunnel = public_url
            
            self.ngrok_enabled = True
            self.ngrok_status_var.set("🟢 Active")
            self.ngrok_url_var.set(public_url.public_url)
            self.ngrok_btn.config(text="🛑 Stop Ngrok Tunnel")
            
            self.log(f"🌐 Ngrok tunnel active: {public_url.public_url}")
            self.log(f"🌐 WebSocket: {public_url.public_url.replace('http', 'ws')}/ws")
            
            messagebox.showinfo("Ngrok Started", 
                              f"Remote access enabled!\n\nPublic URL:\n{public_url.public_url}\n\n"
                              f"Share this URL to access from anywhere.")
        except Exception as e:
            messagebox.showerror("Ngrok Error", f"Failed to start ngrok:\n{e}\n\n"
                               f"Make sure you have ngrok installed:\npip install pyngrok")
            self.log(f"❌ Ngrok failed: {e}")

    def stop_ngrok(self):
        """Stop ngrok tunnel"""
        try:
            if data_store.ngrok_tunnel:
                ngrok.disconnect(data_store.ngrok_tunnel.public_url)
            
            data_store.ngrok_url = None
            data_store.ngrok_tunnel = None
            self.ngrok_enabled = False
            self.ngrok_status_var.set("Not Started")
            self.ngrok_url_var.set("")
            self.ngrok_btn.config(text="🌐 Start Ngrok Tunnel")
            
            self.log("🛑 Ngrok tunnel stopped")
        except Exception as e:
            self.log(f"Error stopping ngrok: {e}")

    def copy(self, text):
        """Copy text to clipboard"""
        if text:
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            self.log("✓ Copied to clipboard")
        else:
            messagebox.showwarning("Nothing to Copy", "No URL available to copy")
    
    def test_api(self):
        """Test API connectivity"""
        import urllib.request
        url = f"http://{get_local_ip()}:{self.api_port}/api/dashboard"
        try:
            with urllib.request.urlopen(url, timeout=5) as r:
                data = json.loads(r.read())
                messagebox.showinfo("✓ API Test Successful", 
                                  f"API is working!\n\n"
                                  f"Total alerts: {data['stats']['total']}\n"
                                  f"Status: {data['status']}\n"
                                  f"WebSocket clients: {len(data_store.websocket_clients)}")
        except Exception as e:
            messagebox.showerror("✗ API Test Failed", f"Could not connect to API:\n{e}")

    def setup_status_bar(self):
        f = ttk.Frame(self.root)
        f.pack(side="bottom", fill="x", padx=5, pady=2)
        
        self.status_var = tk.StringVar(value="● Ready")
        ttk.Label(f, textvariable=self.status_var, relief=tk.SUNKEN, anchor="w").pack(
            side="left", fill="x", expand=True)
        
        self.api_status_var = tk.StringVar(value=f"API: http://{get_local_ip()}:{self.api_port}")
        ttk.Label(f, textvariable=self.api_status_var, relief=tk.SUNKEN).pack(side="right", padx=5)
        
        self.status_indicator = tk.Canvas(f, width=20, height=20, highlightthickness=0)
        self.status_indicator.pack(side="right", padx=5)
        self.status_circle = self.status_indicator.create_oval(5, 5, 15, 15, fill='gray')

    def setup_dashboard_tab(self):
        sf = ttk.Frame(self.dashboard_tab)
        sf.pack(fill="x", padx=10, pady=10)
        
        for lbl, k, c in [("Total", "total", "#3498db"), ("High", "high", "#e74c3c"), 
                         ("Medium", "medium", "#f39c12"), ("Low", "low", "#2ecc71")]:
            card = ttk.Frame(sf, relief=tk.RIDGE, borderwidth=2)
            card.pack(side="left", fill="both", expand=True, padx=5)
            tk.Canvas(card, height=5, bg=c, highlightthickness=0).pack(fill="x")
            v = tk.StringVar(value="0")
            setattr(self, f"{k}_var", v)
            ttk.Label(card, textvariable=v, font=("Segoe UI", 24, "bold")).pack(pady=(10, 0))
            ttk.Label(card, text=f"{lbl} {'Alerts' if k=='total' else 'Severity'}", 
                     font=("Segoe UI", 10)).pack(pady=(0, 10))
        
        cf = ttk.LabelFrame(self.dashboard_tab, text="Controls", padding="10")
        cf.pack(fill="x", padx=10, pady=5)
        bc = ttk.Frame(cf)
        bc.pack()
        
        self.start_btn = ttk.Button(bc, text="▶ Start", command=self.start_ids, width=12)
        self.start_btn.grid(row=0, column=0, padx=5)
        self.stop_btn = ttk.Button(bc, text="■ Stop", command=self.stop_ids, state="disabled", width=12)
        self.stop_btn.grid(row=0, column=1, padx=5)
        ttk.Button(bc, text="🔄 Test", command=self.test_ids, width=12).grid(row=0, column=2, padx=5)
        ttk.Button(bc, text="🌐 IFaces", command=self.list_interfaces, width=12).grid(row=0, column=3, padx=5)
        
        chf = ttk.Frame(self.dashboard_tab)
        chf.pack(fill="both", expand=True, padx=10, pady=5)
        
        lf = ttk.LabelFrame(chf, text="Severity", padding="5")
        lf.pack(side="left", fill="both", expand=True, padx=5)
        self.severity_fig = Figure(figsize=(5,4), dpi=80)
        self.severity_ax = self.severity_fig.add_subplot(111)
        self.severity_canvas = FigureCanvasTkAgg(self.severity_fig, lf)
        self.severity_canvas.get_tk_widget().pack(fill="both", expand=True)
        self.update_severity_chart()
        
        rf = ttk.LabelFrame(chf, text="Timeline", padding="5")
        rf.pack(side="right", fill="both", expand=True, padx=5)
        self.timeline_fig = Figure(figsize=(5,4), dpi=80)
        self.timeline_ax = self.timeline_fig.add_subplot(111)
        self.timeline_canvas = FigureCanvasTkAgg(self.timeline_fig, rf)
        self.timeline_canvas.get_tk_widget().pack(fill="both", expand=True)
        self.update_timeline_chart()

    def setup_alerts_tab(self):
        ff = ttk.Frame(self.alerts_tab)
        ff.pack(fill="x", padx=10, pady=5)
        ttk.Label(ff, text="Filter:").pack(side="left", padx=5)
        self.filter_var = tk.StringVar(value="all")
        for t in ["All", "High", "Medium", "Low"]:
            ttk.Radiobutton(ff, text=t, variable=self.filter_var, value=t.lower()).pack(side="left", padx=5)
        ttk.Button(ff, text="Clear", command=self.clear_alerts).pack(side="right", padx=5)
        
        tf = ttk.Frame(self.alerts_tab)
        tf.pack(fill="both", expand=True, padx=10, pady=5)
        cols = ("timestamp", "severity", "src_ip", "src_port", "dest_ip", "dest_port", "category", "signature")
        self.tree = ttk.Treeview(tf, columns=cols, show="headings", height=20)
        for c, w in zip(cols, [150, 80, 120, 60, 120, 60, 180, 350]):
            self.tree.heading(c, text=c.replace('_', ' ').title())
            self.tree.column(c, width=w)
        vsb = ttk.Scrollbar(tf, orient=tk.VERTICAL, command=self.tree.yview)
        hsb = ttk.Scrollbar(tf, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        tf.grid_rowconfigure(0, weight=1)
        tf.grid_columnconfigure(0, weight=1)
        for tag, bg in [('high', '#ffcccc'), ('medium', '#ffe6cc'), ('low', '#e6ffe6')]:
            self.tree.tag_configure(tag, background=bg)

    def setup_config_tab(self):
        cf = ttk.LabelFrame(self.config_tab, text="Config", padding="15")
        cf.pack(fill="both", expand=True, padx=10, pady=10)
        
        self.suricata_path_var = tk.StringVar(value=DEFAULT_SURICATA_PATH)
        self.config_path_var = tk.StringVar(value=DEFAULT_CONFIG_PATH)
        self.interface_var = tk.StringVar(value="Ethernet")
        self.log_dir_var = tk.StringVar(value=DEFAULT_LOG_DIR)
        
        for i, (lbl, var, w) in enumerate([
            ("Suricata:", self.suricata_path_var, 70),
            ("Config:", self.config_path_var, 70),
            ("Interface:", self.interface_var, 30),
            ("Logs:", self.log_dir_var, 70)
        ]):
            ttk.Label(cf, text=lbl).grid(row=i, column=0, sticky="w", pady=5)
            ttk.Entry(cf, textvariable=var, width=w).grid(row=i, column=1, padx=10, pady=5, sticky="ew")
        cf.columnconfigure(1, weight=1)
        
        af = ttk.LabelFrame(self.config_tab, text="Advanced", padding="15")
        af.pack(fill="x", padx=10, pady=10)
        bg = ttk.Frame(af)
        bg.pack()
        for i, (t, c) in enumerate([
            ("Update Rules", self.update_rules),
            ("Fix Config", self.fix_config),
            ("Allow Local", self.allow_local_attacks)
        ]):
            ttk.Button(bg, text=t, command=c, width=18).grid(row=0, column=i, padx=5)

    def setup_console_tab(self):
        f = ttk.Frame(self.console_tab)
        f.pack(fill="both", expand=True, padx=10, pady=10)
        ttk.Label(f, text="Output", font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=5)
        self.console_text = scrolledtext.ScrolledText(
            f, height=25, state='disabled', font=("Consolas", 9), bg="#1e1e1e", fg="#d4d4d4")
        self.console_text.pack(fill="both", expand=True)

    def clear_alerts(self):
        for i in self.tree.get_children():
            self.tree.delete(i)
        self.alert_stats = {'high': 0, 'medium': 0, 'low': 0, 'total': 0}
        self.category_stats.clear()
        self.alerts_per_minute.clear()
        self.update_stat_displays()
        self.update_severity_chart()
        self.update_timeline_chart()
        data_store.clear_data()
        asyncio.run(broadcast_to_clients({"type": "clear"}))

    def update_stat_displays(self):
        for k in ['total', 'high', 'medium', 'low']:
            getattr(self, f"{k}_var").set(str(self.alert_stats[k]))

    def update_severity_chart(self):
        self.severity_ax.clear()
        sizes = [self.alert_stats[k] for k in ['high', 'medium', 'low']]
        if sum(sizes) == 0:
            self.severity_ax.text(0.5, 0.5, 'No Alerts', ha='center', va='center', 
                                 transform=self.severity_ax.transAxes)
            self.severity_ax.pie([1,1,1], colors=['#ccc']*3)
        else:
            self.severity_ax.pie(sizes, explode=(0.05,0.05,0.05), labels=['High','Med','Low'], 
                                colors=['#e74c3c','#f39c12','#2ecc71'], autopct='%1.1f%%')
        self.severity_ax.axis('equal')
        self.severity_canvas.draw()

    def update_timeline_chart(self):
        self.timeline_ax.clear()
        if not self.alerts_per_minute:
            self.timeline_ax.text(0.5, 0.5, 'No Data', ha='center', va='center', 
                                 transform=self.timeline_ax.transAxes)
        else:
            x = list(range(len(self.alerts_per_minute)))
            y = list(self.alerts_per_minute)
            self.timeline_ax.plot(x, y, color='#3498db', linewidth=2, marker='o', markersize=4)
            self.timeline_ax.fill_between(x, y, alpha=0.3, color='#3498db')
            self.timeline_ax.grid(True, alpha=0.3)
        self.timeline_canvas.draw()

    def start_chart_updates(self):
        def update():
            if self.is_running:
                m = datetime.now().minute
                if m != self.last_minute:
                    self.alerts_per_minute.append(self.current_minute_count)
                    data_store.update_minute_stats(self.current_minute_count)
                    self.current_minute_count = 0
                    self.last_minute = m
                    self.update_timeline_chart()
            self.root.after(5000, update)
        update()

    def log(self, msg):
        self.status_var.set(f"● {msg}")
        print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")
        self.console_text.configure(state='normal')
        self.console_text.insert(tk.END, f"{msg}\n")
        self.console_text.see(tk.END)
        self.console_text.configure(state='disabled')

    def start_ids(self):
        exe = self.suricata_path_var.get()
        cfg = self.config_path_var.get()
        iface = self.interface_var.get()
        logdir = self.log_dir_var.get()
        
        if not os.path.exists(exe):
            return messagebox.showerror("Error", f"Suricata not found: {exe}")
        
        if not os.path.exists(logdir):
            try:
                os.makedirs(logdir)
            except Exception as e:
                return messagebox.showerror("Error", f"Cannot create log directory: {e}")
        
        try:
            self.suricata_process = subprocess.Popen(
                [exe, "-c", cfg, "-i", iface, "-l", logdir, "-k", "none"],
                cwd=os.path.dirname(exe),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )
            
            self.is_running = True
            data_store.is_running = True
            data_store.status_message = f"Running on {iface}"
            data_store.interface_name = iface
            data_store.start_time = datetime.now()
            
            self.stop_event.clear()
            self.start_btn.config(state="disabled")
            self.stop_btn.config(state="normal")
            self.status_indicator.itemconfig(self.status_circle, fill='#2ecc71')
            self.log(f"✓ Suricata started on interface: {iface}")
            
            threading.Thread(target=self.monitor_logs, daemon=True).start()
            threading.Thread(target=self.monitor_process_output, daemon=True).start()
            
            # Broadcast status change to all connected clients
            asyncio.run(broadcast_to_clients({
                "type": "status_change",
                "is_running": True,
                "interface": iface,
                "timestamp": datetime.now().isoformat()
            }))
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start Suricata:\n{e}")
            self.log(f"❌ Start failed: {e}")

    def stop_ids(self):
        if self.suricata_process:
            self.suricata_process.terminate()
            self.suricata_process = None
        
        self.is_running = False
        data_store.is_running = False
        data_store.status_message = "Stopped"
        data_store.start_time = None
        
        self.stop_event.set()
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        self.status_indicator.itemconfig(self.status_circle, fill='gray')
        self.log("■ Suricata stopped")
        
        # Broadcast status change
        asyncio.run(broadcast_to_clients({
            "type": "status_change",
            "is_running": False,
            "timestamp": datetime.now().isoformat()
        }))

    def monitor_process_output(self):
        while self.is_running and self.suricata_process:
            out = self.suricata_process.stdout.readline()
            err = self.suricata_process.stderr.readline()
            
            if out:
                self.root.after(0, self.log, out.strip())
            if err:
                self.root.after(0, self.log, f"ERR: {err.strip()}")
            
            if out == '' and err == '' and self.suricata_process.poll() is not None:
                break

    def monitor_logs(self):
        eve = os.path.join(self.log_dir_var.get(), EVE_JSON_FILE)
        
        # Wait for eve.json to be created
        while not os.path.exists(eve) and not self.stop_event.is_set():
            time.sleep(1)
        
        if self.stop_event.is_set():
            return
        
        self.log(f"📄 Monitoring: {eve}")
        
        with open(eve, 'r') as f:
            # Go to end of file
            f.seek(0, os.SEEK_END)
            
            while self.is_running and not self.stop_event.is_set():
                line = f.readline()
                if line:
                    try:
                        ev = json.loads(line)
                        if ev.get('event_type') == 'alert':
                            self.process_alert(ev)
                    except json.JSONDecodeError:
                        pass
                else:
                    time.sleep(0.1)

    def process_alert(self, ev):
        alert = ev.get('alert', {})
        self.root.after(0, self.add_alert_to_ui,
                       ev.get('timestamp', ''),
                       ev.get('src_ip', ''),
                       ev.get('src_port', ''),
                       ev.get('dest_ip', ''),
                       ev.get('dest_port', ''),
                       alert.get('category', ''),
                       alert.get('signature', ''),
                       alert.get('severity', ''))

    def add_alert_to_ui(self, ts, src_ip, src_port, dest_ip, dest_port, cat, sig, sev):
        try:
            s = int(sev)
            tag = 'high' if s == 1 else 'medium' if s == 2 else 'low'
            self.alert_stats[tag] += 1
        except:
            tag = 'low'
            self.alert_stats['low'] += 1
        
        self.alert_stats['total'] += 1
        self.current_minute_count += 1
        
        if cat:
            self.category_stats[cat] += 1
        
        # Format timestamp
        try:
            dt = datetime.fromisoformat(ts.replace('Z', '+00:00'))
            disp_time = dt.strftime("%Y-%m-%d %H:%M:%S")
        except:
            disp_time = ts
        
        # Add to tree
        self.tree.insert("", 0, values=(disp_time, tag.upper(), src_ip, src_port, 
                                       dest_ip, dest_port, cat, sig), tags=(tag,))
        
        # Keep only last 1000 alerts in UI
        if len(self.tree.get_children()) > 1000:
            self.tree.delete(self.tree.get_children()[-1])
        
        # Update displays
        self.update_stat_displays()
        self.update_severity_chart()
        
        # Prepare alert data for API
        alert_data = {
            'timestamp': disp_time,
            'severity_tag': tag,
            'src_ip': src_ip,
            'src_port': src_port,
            'dest_ip': dest_ip,
            'dest_port': dest_port,
            'category': cat,
            'signature': sig
        }
        
        # Add to data store
        data_store.add_alert(alert_data)
        
        # Broadcast to WebSocket clients
        asyncio.run(broadcast_to_clients({
            "type": "new_alert",
            "alert": alert_data,
            "stats": self.alert_stats.copy(),
            "timestamp": datetime.now().isoformat()
        }))

    def test_ids(self):
        import urllib.request
        self.log("🧪 Sending test request to testmynids.org...")
        
        def run_test():
            try:
                with urllib.request.urlopen("http://testmynids.org/uid/index.html", timeout=10) as r:
                    r.read()
                    self.root.after(0, lambda: self.log("✓ Test request sent successfully"))
                    self.root.after(0, lambda: messagebox.showinfo("Test Complete", 
                        "Test request sent to testmynids.org\n\n"
                        "If Suricata is running correctly, you should see alerts appear shortly.\n"
                        "Check the Alerts tab for results."))
            except Exception as e:
                self.root.after(0, lambda: self.log(f"❌ Test failed: {e}"))
                self.root.after(0, lambda: messagebox.showerror("Test Failed", f"Error: {e}"))
        
        threading.Thread(target=run_test, daemon=True).start()

    def list_interfaces(self):
        try:
            if os.name == 'nt':
                result = subprocess.run(["ipconfig"], capture_output=True, text=True)
            else:
                result = subprocess.run(["ip", "addr"], capture_output=True, text=True)
            
            top = tk.Toplevel(self.root)
            top.title("Network Interfaces")
            top.geometry("600x500")
            
            txt = scrolledtext.ScrolledText(top, wrap=tk.WORD)
            txt.pack(fill="both", expand=True, padx=10, pady=10)
            txt.insert(tk.END, result.stdout)
            txt.configure(state='disabled')
        except Exception as e:
            messagebox.showerror("Error", f"Failed to list interfaces:\n{e}")

    def update_rules(self):
        self.log("📥 Updating Suricata rules...")
        
        def run():
            try:
                result = subprocess.run(["suricata-update"], capture_output=True, text=True)
                if result.returncode == 0:
                    self.root.after(0, lambda: self.log("✓ Rules updated successfully"))
                    self.root.after(0, lambda: messagebox.showinfo("Success", 
                        "Rules updated successfully!\n\nRestart Suricata for changes to take effect."))
                else:
                    self.root.after(0, lambda: self.log(f"❌ Rule update failed"))
                    self.root.after(0, lambda: messagebox.showerror("Error", 
                        f"Failed to update rules:\n{result.stderr}"))
            except Exception as e:
                self.root.after(0, lambda: self.log(f"❌ Error: {e}"))
                self.root.after(0, lambda: messagebox.showerror("Error", 
                    f"Error running suricata-update:\n{e}\n\n"
                    f"Make sure suricata-update is installed and in PATH."))
        
        threading.Thread(target=run, daemon=True).start()

    def fix_config(self):
        cfg = self.config_path_var.get()
        if not os.path.exists(cfg):
            return messagebox.showerror("Error", "Config file not found")
        
        try:
            with open(cfg, 'r') as f:
                lines = f.readlines()
            
            new_lines = []
            in_rules = False
            
            for line in lines:
                if line.strip().startswith("rule-files:"):
                    in_rules = True
                    new_lines.append(line)
                    new_lines.append("  - suricata.rules\n")
                elif in_rules and line.strip().startswith("-"):
                    new_lines.append("# " + line)
                elif in_rules and not line.strip().startswith("-") and not line.strip().startswith("#") and line.strip():
                    in_rules = False
                    new_lines.append(line)
                else:
                    new_lines.append(line)
            
            # Backup original
            shutil.copy(cfg, cfg + ".bak")
            
            with open(cfg, 'w') as f:
                f.writelines(new_lines)
            
            messagebox.showinfo("Success", 
                "Configuration fixed!\n\nBackup saved as: " + cfg + ".bak\n\n"
                "Restart Suricata for changes to take effect.")
            self.log("✓ Config fixed successfully")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to fix config:\n{e}")

    def allow_local_attacks(self):
        cfg = self.config_path_var.get()
        if not os.path.exists(cfg):
            return messagebox.showerror("Error", "Config file not found")
        
        try:
            with open(cfg, 'r') as f:
                content = f.read()
            
            if 'EXTERNAL_NET: "!$HOME_NET"' in content:
                new_content = content.replace('EXTERNAL_NET: "!$HOME_NET"', 'EXTERNAL_NET: "any"')
                
                # Backup original
                shutil.copy(cfg, cfg + ".bak_net")
                
                with open(cfg, 'w') as f:
                    f.write(new_content)
                
                messagebox.showinfo("Success", 
                    "Local attack detection enabled!\n\n"
                    "Backup saved as: " + cfg + ".bak_net\n\n"
                    "Restart Suricata for changes to take effect.")
                self.log("✓ Local attacks enabled")
            else:
                messagebox.showinfo("Info", "Local attacks already enabled or setting not found")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to modify config:\n{e}")

if __name__ == "__main__":
    root = tk.Tk()
    app = NetShieldIDS(root)
    root.mainloop()