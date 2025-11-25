from collections import defaultdict
from datetime import datetime, timedelta

# For time-window tracking
port_scan_tracker = defaultdict(dict)       # src_ip -> {port: last_seen_time}
syn_flood_tracker = defaultdict(list)       # src_ip -> [timestamps]


def detect_port_scan(src_ip, dst_port, threshold=15, window_seconds=30):
    """
    Detect if one IP is hitting too many different destination ports
    within a recent time window (e.g., last 30 seconds).
    """
    if dst_port is None:
        return None

    now = datetime.now()
    ports = port_scan_tracker[src_ip]

    # Record/refresh this port with current time
    try:
        dport = int(dst_port)
    except Exception:
        return None

    ports[dport] = now

    # Drop old ports outside the time window
    cutoff = now - timedelta(seconds=window_seconds)
    for p, t in list(ports.items()):
        if t < cutoff:
            del ports[p]

    # Count how many unique ports remain in the window
    unique_ports = len(ports)
    if unique_ports > threshold:
        return (
            f"[{now.isoformat()}] ⚠️ Port Scan Detected from {src_ip} "
            f"(unique ports in last {window_seconds}s: {unique_ports})"
        )

    return None


def detect_syn_flood(src_ip, flags, threshold=50, window_seconds=30):
    """
    Detect if SYN packets from one IP exceed threshold within
    a recent time window (e.g., last 30 seconds).
    """
    if not flags:
        return None

    now = datetime.now()

    # Only count packets where SYN flag is present
    if "S" in flags:
        times = syn_flood_tracker[src_ip]
        times.append(now)

        # Drop timestamps outside the window
        cutoff = now - timedelta(seconds=window_seconds)
        syn_flood_tracker[src_ip] = [t for t in times if t >= cutoff]

        syn_count = len(syn_flood_tracker[src_ip])
        if syn_count > threshold:
            return (
                f"[{now.isoformat()}] 🚨 Possible SYN Flood from {src_ip} "
                f"(SYN packets in last {window_seconds}s: {syn_count})"
            )

    return None


def detect_invalid_ip(src_ip):
    """
    Flag private IPs for demo.
    Note: private IPs are normal inside local networks;
    this is just to show the detector working.
    """
    private_prefixes = ("10.", "192.168.", "172.")
    if src_ip.startswith(private_prefixes):
        return f"[{datetime.now().isoformat()}] ⚠️ Private/internal IP traffic (for demo): {src_ip}"
    return None
