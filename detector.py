from collections import defaultdict
from datetime import datetime

# Track packets from each source
port_scan_tracker = defaultdict(set)
syn_flood_tracker = defaultdict(int)

def detect_port_scan(src_ip, dst_port, threshold=15):
    """Detect if one IP is hitting too many different destination ports."""
    if dst_port is None:
        return None
    try:
        port_scan_tracker[src_ip].add(int(dst_port))
    except Exception:
        # if dport isn't an int, ignore for port-scan counting
        return None
    if len(port_scan_tracker[src_ip]) > threshold:
        return f"[{datetime.now().isoformat()}] ⚠️ Port Scan Detected from {src_ip} (ports seen: {len(port_scan_tracker[src_ip])})"
    return None

def detect_syn_flood(src_ip, flags, threshold=50):
    """Detect if SYN packets from one IP exceed threshold."""
    if not flags:
        return None
    # count if SYN bit present (flags like 'S', 'SA', etc.)
    if "S" in flags:
        syn_flood_tracker[src_ip] += 1
        if syn_flood_tracker[src_ip] > threshold:
            return f"[{datetime.now().isoformat()}] 🚨 Possible SYN Flood from {src_ip} (SYN count: {syn_flood_tracker[src_ip]})"
    return None

def detect_invalid_ip(src_ip):
    """Flag private IPs for demo (note: private IPs are normal inside local networks)."""
    # 172.16.0.0 - 172.31.255.255 are private; naive prefix check for demo
    private_prefixes = ("10.", "192.168.", "172.")
    if src_ip.startswith(private_prefixes):
        return f"[{datetime.now().isoformat()}] ⚠️ Private/internal IP traffic (for demo): {src_ip}"
    return None
