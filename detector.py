# detector.py
"""
Detection logic for the IDS.
- Port scan detection (unique destination ports per source)
- SYN flood detection (count SYNs)
- Half-open handshake heuristic
- ICMP ping sweep detection
- Packet rate detection
All functions return either a human-readable alert string or None.
"""

from collections import defaultdict, deque
from datetime import datetime, timedelta

# Trackers (module-level so state persists while sniffer runs)
port_scan_tracker = defaultdict(set)         # {src_ip: set(dports)}
syn_flood_tracker = defaultdict(int)        # {src_ip: syn_count}
handshake_tracker = defaultdict(lambda: {"syn": 0, "ack": 0, "last_seen": None})
ping_tracker = defaultdict(lambda: deque())  # {src_ip: deque((timestamp, dst_ip))}
packet_times = defaultdict(deque)            # {src_ip: deque(timestamps)}

# thresholds (tweak as needed)
PORT_SCAN_THRESHOLD = 15
SYN_FLOOD_THRESHOLD = 50
PING_SWEEP_HOSTS = 8
PING_SWEEP_WINDOW = 30
PACKET_RATE_WINDOW = 5
PACKET_RATE_THRESHOLD = 200

# A simple "alert log" (optional)
alert_log = []


def reset_detectors_state():
    """Clear all internal detector state (useful for fresh tests)."""
    port_scan_tracker.clear()
    syn_flood_tracker.clear()
    handshake_tracker.clear()
    ping_tracker.clear()
    packet_times.clear()
    alert_log.clear()


def detect_port_scan(src_ip, dst_port, threshold=PORT_SCAN_THRESHOLD):
    """
    If a source contacts many unique destination ports, flag a port scan.
    Returns alert string or None.
    """
    if dst_port is None:
        return None
    try:
        port_scan_tracker[src_ip].add(int(dst_port))
    except Exception:
        # non-int ports (rare) are ignored for counting
        return None
    count = len(port_scan_tracker[src_ip])
    if count > threshold:
        msg = f"[{datetime.now().isoformat()}] Port Scan Detected from {src_ip} (ports seen: {count})"
        alert_log.append(msg)
        return msg
    return None


def detect_syn_flood(src_ip, flags, threshold=SYN_FLOOD_THRESHOLD):
    """
    Count SYN-only packets from a source. If count exceeds threshold, warn.
    Note: 'S' present and 'A' absent usually indicates initial SYN.
    """
    if not flags:
        return None
    if "S" in flags and "A" not in flags:
        syn_flood_tracker[src_ip] += 1
        if syn_flood_tracker[src_ip] > threshold:
            msg = f"[{datetime.now().isoformat()}] 🚨 Possible SYN Flood from {src_ip} (SYN count: {syn_flood_tracker[src_ip]})"
            alert_log.append(msg)
            return msg
    return None


def detect_half_open_handshakes(src_ip, flags, threshold=100):
    """
    Heuristic: many SYNs compared to ACKs indicate half-open handshake attempts.
    """
    if not flags:
        return None
    entry = handshake_tracker[src_ip]
    if "S" in flags and "A" not in flags:
        entry["syn"] += 1
        entry["last_seen"] = datetime.now()
    if "A" in flags and "S" not in flags:
        entry["ack"] += 1
        entry["last_seen"] = datetime.now()

    if entry["syn"] > threshold and entry["syn"] > (entry["ack"] * 3 + 5):
        msg = f"[{datetime.now().isoformat()}] Suspicious half-open handshakes from {src_ip} (syns: {entry['syn']}, acks: {entry['ack']})"
        alert_log.append(msg)
        # dampen counters to avoid repeating the same alert endlessly
        entry["syn"] = entry["syn"] // 2
        entry["ack"] = entry["ack"] // 2
        return msg
    return None


def detect_ping_sweep(src_ip, dst_ip, icmp_type, hosts_threshold=PING_SWEEP_HOSTS, window=PING_SWEEP_WINDOW):
    """
    Detect ICMP ping sweep: a single source sends echo requests (ICMP type 8)
    to many different destinations within a short time window.
    """
    if icmp_type is None:
        return None
    try:
        if int(icmp_type) != 8:
            return None  # not an echo-request
    except Exception:
        return None

    now = datetime.now()
    dq = ping_tracker[src_ip]
    dq.append((now, dst_ip))

    cutoff = now - timedelta(seconds=window)
    while dq and dq[0][0] < cutoff:
        dq.popleft()

    unique_hosts = {entry[1] for entry in dq}
    count = len(unique_hosts)
    if count >= hosts_threshold:
        msg = f"[{datetime.now().isoformat()}] ICMP Ping Sweep detected from {src_ip} (hosts probed in last {window}s: {count})"
        alert_log.append(msg)
        # clear to avoid immediate repeats
        ping_tracker[src_ip].clear()
        return msg
    return None


def detect_invalid_ip(src_ip):
    """
    For demonstration: flag private/internal IPs so students notice local traffic.
    (Private IPs are normal; this is purely informational.)
    """
    private_prefixes = ("10.", "192.168.", "172.")
    if any(src_ip.startswith(p) for p in private_prefixes):
        msg = f"[{datetime.now().isoformat()}] Private/internal IP traffic (for demo): {src_ip}"
        return msg
    return None


def detect_packet_rate(src_ip, window_seconds=PACKET_RATE_WINDOW, threshold=PACKET_RATE_THRESHOLD):
    """
    Flag a source that sends too many packets within a short window.
    """
    now = datetime.now()
    dq = packet_times[src_ip]
    dq.append(now)
    cutoff = now - timedelta(seconds=window_seconds)
    while dq and dq[0] < cutoff:
        dq.popleft()
    if len(dq) > threshold:
        msg = f"[{datetime.now().isoformat()}] High packet rate from {src_ip} ({len(dq)} pkts in last {window_seconds}s)"
        alert_log.append(msg)
        # trim to avoid repeat spamming
        packet_times[src_ip] = deque(list(dq)[-threshold//2:])
        return msg
    return None
