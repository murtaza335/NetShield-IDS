import pickle
import pandas as pd
import warnings
import sys

warnings.filterwarnings('ignore')

from scapy.all import sniff, IP, TCP, UDP, ICMP
from collections import defaultdict
from datetime import datetime
import time

# Load model, encoders, and scaler
try:
    with open('model.pkl', 'rb') as f:
        model = pickle.load(f)
    with open('encoders.pkl', 'rb') as f:
        encoders = pickle.load(f)
    with open('scaler.pkl', 'rb') as f:
        scaler = pickle.load(f)
except FileNotFoundError as e:
    print(f"Error: Required model file not found - {e}")
    sys.exit(1)

production_features = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "urgent", "wrong_fragment", "count", "srv_count", "serror_rate",
    "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate",
    "diff_srv_rate", "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate"
]

packet_buffer = []
buffer_size = 100
total_packets = 0
total_attacks = 0
total_normal = 0

connection_tracker = defaultdict(lambda: {
    'ports': set(),
    'packet_count': 0,
    'syn_count': 0,
    'connections': 0,
    'start_time': None,
    'last_time': None,
    'packets_per_port': defaultdict(int),
    'total_bytes': 0
})


def extract_features_from_packets(packets):
    flows = defaultdict(lambda: {
        'packets': [],
        'start_time': None,
        'src_bytes': 0,
        'dst_bytes': 0,
        'protocol': None,
        'service': 'private',
        'flag': 'SF',
        'src_ip': None,
        'dst_ip': None,
        'src_port': None,
        'dst_port': None
    })

    for pkt in packets:
        if IP not in pkt:
            continue

        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst

        if TCP in pkt:
            protocol = 'tcp'
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            flow_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-tcp"
        elif UDP in pkt:
            protocol = 'udp'
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport
            flow_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-udp"
        elif ICMP in pkt:
            protocol = 'icmp'
            src_port = dst_port = 0
            flow_key = f"{src_ip}-{dst_ip}-icmp"
        else:
            continue

        flow = flows[flow_key]
        flow['packets'].append(pkt)
        flow['protocol'] = protocol
        flow['src_ip'] = src_ip
        flow['dst_ip'] = dst_ip
        flow['src_port'] = src_port
        flow['dst_port'] = dst_port

        if flow['start_time'] is None:
            flow['start_time'] = pkt.time

        if hasattr(pkt, 'len'):
            flow['src_bytes'] += pkt.len

    return flows


def create_nslkdd_features(flow_data, src_ip):
    packets = flow_data['packets']
    duration = packets[-1].time - packets[0].time if len(packets) > 1 else 0
    protocol_type = flow_data['protocol']

    dst_port = flow_data['dst_port']
    if dst_port == 80:
        service = 'http'
    elif dst_port == 22:
        service = 'ssh'
    elif dst_port == 23:
        service = 'telnet'
    elif dst_port == 21:
        service = 'ftp'
    elif dst_port == 25:
        service = 'smtp'
    elif dst_port == 53:
        service = 'domain'
    else:
        service = 'private'

    src_bytes = flow_data['src_bytes']
    dst_bytes = flow_data.get('dst_bytes', 0)
    src_tracker = connection_tracker[src_ip]
    count = src_tracker['connections']
    srv_count = count

    features = {
        'duration': duration,
        'protocol_type': protocol_type,
        'service': service,
        'flag': 'SF',
        'src_bytes': src_bytes,
        'dst_bytes': dst_bytes,
        'land': 0,
        'urgent': 0,
        'wrong_fragment': 0,
        'count': min(count, 511),
        'srv_count': min(srv_count, 511),
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

    return features


def detect_attack_heuristics(flow_data, src_ip):
    """Improved heuristic detection that distinguishes DDoS from port scans"""
    packets = flow_data['packets']
    src_tracker = connection_tracker[src_ip]
    dst_port = flow_data['dst_port']

    num_ports = len(src_tracker['ports'])
    num_packets = src_tracker['packet_count']
    time_window = src_tracker['last_time'] - src_tracker['start_time'] if src_tracker['start_time'] else 0

    # Packets to this specific port
    packets_to_this_port = src_tracker['packets_per_port'][dst_port]

    # Calculate packet rate
    packet_rate = num_packets / time_window if time_window > 0 else 0

    # PRIORITY 1: DDoS Detection (MUST check FIRST)
    # High volume to SAME port = DDoS, not port scan
    if packets_to_this_port > 50:  # Many packets to same port
        return 'DDoS Attack', True

    if packet_rate > 100:  # High packet rate (>100 pkt/sec)
        return 'DDoS Attack', True

    if num_packets > 200 and num_ports < 5:  # Many packets, few ports = flood
        return 'DDoS Attack', True

    # SYN Flood - many SYNs to same port
    if src_tracker['syn_count'] > 50 and num_ports < 3:
        return 'SYN Flood', True

    # PRIORITY 2: Port Scan Detection
    # Many DIFFERENT ports with FEW packets each = port scan
    if num_ports > 15 and (num_packets / num_ports) < 3:  # Low packets per port
        return 'Port Scan', True

    if num_ports > 10 and num_packets < 100:  # Many ports, low total packets
        return 'Port Scan', True

    # Fast scan - touching many ports quickly
    if num_ports > 20 and time_window < 5:
        return 'Fast Port Scan', True

    # PRIORITY 3: Other attacks
    if src_tracker['connections'] > 100:
        return 'Connection Flood', True

    return 'Normal', False


def process_buffer():
    global packet_buffer, total_attacks, total_normal

    if len(packet_buffer) == 0:
        return

    flows = extract_features_from_packets(packet_buffer)

    for flow_key, flow_data in flows.items():
        src_ip = flow_data['src_ip']
        dst_ip = flow_data['dst_ip']
        src_port = flow_data['src_port']
        dst_port = flow_data['dst_port']
        protocol = flow_data['protocol']

        features = create_nslkdd_features(flow_data, src_ip)

        for col in ['protocol_type', 'service', 'flag']:
            try:
                features[col] = encoders[col].transform([features[col]])[0]
            except:
                features[col] = 0

        df = pd.DataFrame([features])[production_features]
        scaled = scaler.transform(df)

        prediction = model.predict(scaled)[0]
        proba = model.predict_proba(scaled)[0]
        confidence = max(proba) * 100

        attack_type, is_heuristic_attack = detect_attack_heuristics(flow_data, src_ip)
        is_ml_attack = (prediction == 0 and confidence > 60)

        timestamp = datetime.now().strftime('%H:%M:%S')

        if is_ml_attack or is_heuristic_attack:
            total_attacks += 1
            detection = "ML" if is_ml_attack else "Heuristic"
            if is_ml_attack and is_heuristic_attack:
                detection = "ML+Heuristic"

            src_tracker = connection_tracker[src_ip]
            pkt_rate = src_tracker['packet_count'] / max((src_tracker['last_time'] - src_tracker['start_time']),
                                                         0.001) if src_tracker['start_time'] else 0

            print(
                f"🚨 [{timestamp}] ATTACK: {attack_type} | {src_ip}:{src_port} -> {dst_ip}:{dst_port} | {protocol.upper()} | {detection} | Conf: {confidence:.1f}% | Ports: {len(src_tracker['ports'])} | PktRate: {pkt_rate:.1f}/s | TotalPkts: {src_tracker['packet_count']}")
        else:
            total_normal += 1

    packet_buffer = []


def capture_packet(packet):
    global packet_buffer, total_packets

    if IP in packet:
        dst_ip = packet[IP].dst
        if dst_ip.startswith(('224.', '239.')) or dst_ip.endswith('.255'):
            return

        src_ip = packet[IP].src
        src_tracker = connection_tracker[src_ip]
        src_tracker['packet_count'] += 1
        src_tracker['connections'] += 1

        current_time = time.time()
        if src_tracker['start_time'] is None:
            src_tracker['start_time'] = current_time
        src_tracker['last_time'] = current_time

        if TCP in packet:
            dst_port = packet[TCP].dport
            src_tracker['ports'].add(dst_port)
            src_tracker['packets_per_port'][dst_port] += 1
            if packet[TCP].flags & 0x02:
                src_tracker['syn_count'] += 1
        elif UDP in packet:
            dst_port = packet[UDP].dport
            src_tracker['ports'].add(dst_port)
            src_tracker['packets_per_port'][dst_port] += 1

    packet_buffer.append(packet)
    total_packets += 1

    if len(packet_buffer) >= buffer_size:
        process_buffer()


print("IDS Active | Monitoring br-356f705f7dd6 | Buffer: 100 packets\n")

try:
    sniff(prn=capture_packet, store=False, iface="br-356f705f7dd6", promisc=True)
except KeyboardInterrupt:
    if len(packet_buffer) > 0:
        process_buffer()

    print(f"\n\nStopped | Packets: {total_packets} | Normal: {total_normal} | Attacks: {total_attacks}")
    if (total_attacks + total_normal) > 0:
        attack_rate = (total_attacks / (total_attacks + total_normal) * 100)
        print(f"Attack Rate: {attack_rate:.2f}%\n")
except Exception as e:
    print(f"Error: {e}")