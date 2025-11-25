# logger.py
"""
CSV logging for captured packets.
Creates logs/traffic_log.csv (if missing) and appends rows with each packet.
"""

import os
from datetime import datetime
import pandas as pd

LOG_DIR = "logs"
LOG_PATH = os.path.join(LOG_DIR, "traffic_log.csv")

def init_log():
    """Ensure logs directory and CSV header exist."""
    if not os.path.exists(LOG_DIR):
        os.makedirs(LOG_DIR)
    if not os.path.exists(LOG_PATH):
        df = pd.DataFrame(columns=["timestamp", "src_ip", "dst_ip", "protocol", "sport", "dport"])
        df.to_csv(LOG_PATH, index=False)

def log_packet(src_ip, dst_ip, protocol, sport, dport):
    """
    Append a single packet row to the CSV.
    Use a small DataFrame write to avoid concurrency issues.
    """
    timestamp = datetime.now().isoformat()
    row = {
        "timestamp": timestamp,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "protocol": protocol,
        "sport": sport,
        "dport": dport
    }
    try:
        df = pd.DataFrame([row])
        df.to_csv(LOG_PATH, mode="a", header=False, index=False)
    except Exception as e:
        print(f"[LoggerError] Could not write log: {e}")
