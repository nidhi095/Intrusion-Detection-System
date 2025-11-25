# detector.py
from collections import defaultdict, deque
from datetime import datetime, timedelta

# Port-scan: track unique destination ports per src
port_scan_tracker = defaultdict(set)

# SYN flood: simple count of SYNs per src
syn_flood_tracker = defaultdict(int)

# ICMP ping sweep: src -> {dst: last_seen}
ping_sweep_tracker = defaultdict(dict)

# Half-open handshake: src -> list[timestamps]
half_open_tracker = defaultdict(list)

# Packet rate: keep short deque of timestamps per src
packet_rate_tracker = defaultdict(lambda: deque(maxlen=1000))

# Protocol stats (global counter passed in; this is optional)
# App protocol identification: we don't need internal state, just mapping
# DNS flood: simple per-src counter with decay
dns_tracker = defaultdict(lambda: deque())

# TTL baseline: store recent TTL values per src to detect anomalies
ttl_baseline = defaultdict(lambda: deque(maxlen=20))

def reset_detectors_state():
    port_scan_tracker.clear()
    syn_flood_tracker.clear()
    ping_sweep_tracker.clear()
    half_open_tracker.clear()
    packet_rate_tracker.clear()
    dns_tracker.clear()
    ttl_baseline.clear()

# ----- Port scan -----
def detect_port_scan(src_ip, dst_port, threshold=15):
    if dst_port is None:
        return None
    try:
        port_scan_tracker[src_ip].add(int(dst_port))
    except Exception:
        return None
    c = len(port_scan_tracker[src_ip])
    if c > threshold:
        return f"[{datetime.now().isoformat()}] ⚠️ Port Scan Detected from {src_ip} (unique ports in last run: {c})"
    return None

# ----- SYN flood (simple count) -----
def detect_syn_flood(src_ip, flags, threshold=80):
    if not flags:
        return None
    if "S" in flags:
        syn_flood_tracker[src_ip] += 1
        if syn_flood_tracker[src_ip] > threshold:
            return f"[{datetime.now().isoformat()}] 🚨 Possible SYN Flood from {src_ip} (SYN count: {syn_flood_tracker[src_ip]})"
    return None

# ----- Half-open handshake -----
def detect_half_open_handshakes(src_ip, flags, threshold=30, window_seconds=30):
    if not flags:
        return None
    now = datetime.now()
    pending = half_open_tracker[src_ip]
    cutoff = now - timedelta(seconds=window_seconds)
    # remove old pending SYN timestamps
    pending[:] = [t for t in pending if t >= cutoff]
    if "S" in flags and "A" not in flags:
        pending.append(now)
    if "A" in flags and pending:
        # consider an ACK completes one pending SYN
        pending.pop(0)
    if len(pending) > threshold:
        return f"[{now.isoformat()}] 🚨 Excessive half-open TCP handshakes from {src_ip} (pending SYNs: {len(pending)})"
    return None

# ----- ICMP Ping Sweep -----
def detect_ping_sweep(src_ip, dst_ip, icmp_type, threshold=10, window_seconds=30):
    if dst_ip is None or icmp_type is None:
        return None
    # ICMP echo request has type 8
    if icmp_type != 8:
        return None
    now = datetime.now()
    hosts = ping_sweep_tracker[src_ip]
    hosts[dst_ip] = now
    cutoff = now - timedelta(seconds=window_seconds)
    for h, t in list(hosts.items()):
        if t < cutoff:
            del hosts[h]
    unique_hosts = len(hosts)
    if unique_hosts > threshold:
        return f"[{now.isoformat()}] ⚠️ ICMP Ping Sweep detected from {src_ip} (hosts probed: {unique_hosts} in {window_seconds}s)"
    return None

# ----- Packet rate / congestion detection -----
def detect_packet_rate(src_ip, per_seconds=1, threshold_pps=200):
    """
    Call this once per packet for src_ip. It stores timestamps and computes packets/sec.
    If packets/sec exceed threshold -> alert.
    """
    now = datetime.now().timestamp()
    dq = packet_rate_tracker[src_ip]
    dq.append(now)
    # count timestamps within last per_seconds
    cutoff = now - per_seconds
    # deque is short; do linear scan
    cnt = sum(1 for t in dq if t >= cutoff)
    if cnt > threshold_pps:
        return f"[{datetime.now().isoformat()}] 🚨 High packet rate from {src_ip} ({cnt} pkt/sec)"
    return None

# ----- Protocol stats -----
def detect_protocol_stats(protocol_counter, report_every=0):
    """
    This function is a placeholder: protocol_counter is maintained in main.py.
    We return None (no immediate alert). You can adapt to print periodic stats externally.
    """
    return None

# ----- App-layer (port-based) fingerprinting -----
PORT_SERVICE_MAP = {
    80: "HTTP",
    443: "HTTPS",
    53: "DNS",
    22: "SSH",
    21: "FTP",
    23: "TELNET",
    25: "SMTP",
    110: "POP3",
    143: "IMAP",
    3389: "RDP",
}

def detect_app_protocol(src_ip, dst_ip, protocol, sport, dport):
    if dport is None:
        return None
    try:
        service = PORT_SERVICE_MAP.get(int(dport))
    except Exception:
        service = None
    if service:
        return f"[{datetime.now().isoformat()}] ℹ️ Application-level traffic detected: {service} ({src_ip} -> {dst_ip}:{dport})"
    return None

# ----- DNS flood detection -----
def detect_dns_flood(src_ip, window_seconds=10, threshold=30):
    now = datetime.now().timestamp()
    dq = dns_tracker[src_ip]
    dq.append(now)
    cutoff = now - window_seconds
    while dq and dq[0] < cutoff:
        dq.popleft()
    if len(dq) > threshold:
        return f"[{datetime.now().isoformat()}] 🚨 Possible DNS flood from {src_ip} ({len(dq)} DNS queries in {window_seconds}s)"
    return None

# ----- TTL anomaly detection -----
def detect_ttl_anomaly(src_ip, ttl_value, deviation_threshold=20):
    """
    Maintain recent TTL samples for an IP; if a new TTL deviates by more than
    deviation_threshold from the median of recent TTLs, flag as suspicious (possible spoofing).
    """
    if ttl_value is None:
        return None
    dq = ttl_baseline[src_ip]
    dq.append(ttl_value)
    if len(dq) < 5:
        return None
    # compute median-ish baseline
    arr = sorted(dq)
    median = arr[len(arr)//2]
    if abs(ttl_value - median) > deviation_threshold:
        return f"[{datetime.now().isoformat()}] ⚠️ TTL anomaly from {src_ip} (ttl={ttl_value}, baseline~{median})"
    return None
