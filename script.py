import pickle
import pandas as pd
import warnings

warnings.filterwarnings('ignore')

from scapy.all import sniff, IP, TCP, UDP, ICMP, wrpcap
from collections import defaultdict
import time
from datetime import datetime
import subprocess
import os
import tempfile

# Load model, encoders, and scaler
print("Loading model components...")
with open('model.pkl', 'rb') as f:
    model = pickle.load(f)
with open('encoders.pkl', 'rb') as f:
    encoders = pickle.load(f)
with open('scaler.pkl', 'rb') as f:
    scaler = pickle.load(f)

production_features = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "urgent", "wrong_fragment", "count", "srv_count", "serror_rate",
    "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate",
    "diff_srv_rate", "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate"
]

# Packet buffer for CICFlowMeter
packet_buffer = []
buffer_size = 100  # Process every 100 packets
temp_pcap = tempfile.NamedTemporaryFile(suffix='.pcap', delete=False)
temp_pcap_path = temp_pcap.name
temp_pcap.close()


def run_cicflowmeter(pcap_file):
    """Run CICFlowMeter on pcap file and return flows"""
    try:
        output_dir = tempfile.mkdtemp()

        # Run CICFlowMeter
        cmd = f"cicflowmeter -f {pcap_file} -c {output_dir}"
        subprocess.run(cmd, shell=True, capture_output=True, timeout=10)

        # Read generated CSV
        csv_files = [f for f in os.listdir(output_dir) if f.endswith('.csv')]
        if csv_files:
            csv_path = os.path.join(output_dir, csv_files[0])
            flows = pd.read_csv(csv_path)

            # Cleanup
            os.remove(csv_path)
            os.rmdir(output_dir)

            return flows
    except Exception as e:
        print(f"CICFlowMeter error: {e}")

    return None


def map_cicflow_to_nslkdd(flow_row):
    """Map CICFlowMeter features to NSL-KDD features"""
    try:
        # Basic mappings (simplified - you may need to adjust based on actual CICFlowMeter output)
        features = {
            'duration': flow_row.get('Flow Duration', 0) / 1000000,  # microseconds to seconds
            'protocol_type': 'tcp' if 'TCP' in str(flow_row.get('Protocol', '')) else 'udp',
            'service': 'http' if flow_row.get('Dst Port', 0) == 80 else 'private',
            'flag': 'SF',  # Default flag
            'src_bytes': flow_row.get('Tot Fwd Pkts', 0),
            'dst_bytes': flow_row.get('Tot Bwd Pkts', 0),
            'land': 0,
            'urgent': 0,
            'wrong_fragment': 0,
            'count': flow_row.get('Flow Pkts/s', 0),
            'srv_count': flow_row.get('Flow Pkts/s', 0),
            'serror_rate': 0.0,
            'srv_serror_rate': 0.0,
            'rerror_rate': 0.0,
            'srv_rerror_rate': 0.0,
            'same_srv_rate': 1.0,
            'diff_srv_rate': 0.0,
            'srv_diff_host_rate': 0.0,
            'dst_host_count': 10,
            'dst_host_srv_count': 10,
            'dst_host_same_srv_rate': 1.0,
            'dst_host_diff_srv_rate': 0.0,
            'dst_host_same_src_port_rate': 0.5,
            'dst_host_srv_diff_host_rate': 0.0,
            'dst_host_serror_rate': 0.0,
            'dst_host_srv_serror_rate': 0.0,
            'dst_host_rerror_rate': 0.0,
            'dst_host_srv_rerror_rate': 0.0
        }

        src_ip = flow_row.get('Src IP', 'Unknown')
        dst_ip = flow_row.get('Dst IP', 'Unknown')

        return features, src_ip, dst_ip
    except Exception as e:
        return None, None, None


def classify_attack_from_cicflow(flow_row):
    """Classify attack type based on CICFlowMeter features"""
    try:
        flow_pkts = flow_row.get('Flow Pkts/s', 0)
        fwd_pkts = flow_row.get('Tot Fwd Pkts', 0)

        # DoS - High packet rate
        if flow_pkts > 1000:
            return 'DoS Attack'

        # Port Scan - Many flows to different ports
        if fwd_pkts < 5 and flow_row.get('Flow Duration', 0) < 1000:
            return 'Probe (Port Scan)'

        return 'Suspicious Activity'
    except:
        return 'Unknown Attack'


def process_buffer():
    """Process buffered packets with CICFlowMeter"""
    global packet_buffer

    if len(packet_buffer) == 0:
        return

    # Save packets to pcap
    wrpcap(temp_pcap_path, packet_buffer)

    # Run CICFlowMeter
    flows = run_cicflowmeter(temp_pcap_path)

    if flows is not None and len(flows) > 0:
        for _, flow in flows.iterrows():
            result = map_cicflow_to_nslkdd(flow)
            if result[0] is None:
                continue

            features, src_ip, dst_ip = result

            # Encode categorical features
            for col in ['protocol_type', 'service', 'flag']:
                try:
                    features[col] = encoders[col].transform([features[col]])[0]
                except:
                    features[col] = 0

            # Create DataFrame and scale
            df = pd.DataFrame([features])[production_features]
            scaled = scaler.transform(df)

            # Predict
            prediction = model.predict(scaled)[0]
            proba = model.predict_proba(scaled)[0]
            confidence = max(proba) * 100

            if prediction == 0 and confidence > 75:
                attack_type = classify_attack_from_cicflow(flow)

                timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                print(f"\n[ALERT] {timestamp}")
                print(f"  Type: {attack_type}")
                print(f"  Source: {src_ip} -> Destination: {dst_ip}")
                print(f"  Confidence: {confidence:.2f}%")

    # Clear buffer
    packet_buffer = []


def capture_packet(packet):
    """Capture packets and buffer them"""
    global packet_buffer

    # Filter out multicast/broadcast
    if IP in packet:
        dst_ip = packet[IP].dst
        if dst_ip.startswith(('224.', '239.')) or dst_ip.endswith('.255'):
            return

    packet_buffer.append(packet)

    # Process when buffer is full
    if len(packet_buffer) >= buffer_size:
        print(f"Processing {len(packet_buffer)} packets...")
        process_buffer()


# Start packet capture
print("\n" + "=" * 60)
print("Network Intrusion Detection System - CICFlowMeter Mode")
print("=" * 60)
print("Monitoring network traffic... Press Ctrl+C to stop\n")

try:
    sniff(prn=capture_packet, store=False)
except KeyboardInterrupt:
    print("\n\nProcessing remaining packets...")
    process_buffer()
    print("Monitoring stopped.")
    os.remove(temp_pcap_path)
except PermissionError:
    print("\nERROR: Need administrator/root privileges!")
    print("Run as: sudo python script.py  (Linux/Mac)")
    print("Or run Command Prompt as Administrator (Windows)")