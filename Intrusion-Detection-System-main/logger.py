import pandas as pd
from datetime import datetime
import os

LOG_DIR = "logs"
LOG_PATH = os.path.join(LOG_DIR, "traffic_log.csv")

def init_log():
    if not os.path.exists(LOG_DIR):
        os.makedirs(LOG_DIR)
    if not os.path.exists(LOG_PATH):
        df = pd.DataFrame(columns=["timestamp", "src_ip", "dst_ip", "protocol", "sport", "dport"])
        df.to_csv(LOG_PATH, index=False)

def log_packet(src_ip, dst_ip, protocol, sport, dport):
    """Log each packet to CSV file (appends)."""
    timestamp = datetime.now().isoformat()
    new_entry = {
        "timestamp": timestamp,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "protocol": protocol,
        "sport": sport,
        "dport": dport
    }
    try:
        df = pd.DataFrame([new_entry])
        # append without header
        df.to_csv(LOG_PATH, mode="a", header=False, index=False)
    except Exception as e:
        # If logging fails, print error but don't crash the sniffer
        print(f"[LoggerError] Could not write log: {e}")
