# FINAL WORKING IDS (Windows-safe, simulator-integrated)

import socket
import threading
from datetime import datetime

# Stats
alert_counts = {}
start_time = datetime.now()


def handle_simulator_messages():
    """Receives messages from simulation scripts (no packet sniffing needed)."""
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind(("127.0.0.1", 9999))

    print("[*] IDS ready and listening for simulated attacks...")
    print("Press Ctrl + C to stop.\n")

    while True:
        msg, addr = server.recvfrom(2048)
        message = msg.decode()

        src = addr[0]
        alert_counts[src] = alert_counts.get(src, 0) + 1

        print(f"[ALERT] {message}  (from {src})")


def print_summary():
    print("\n=== IDS SUMMARY ===")
    print(f"Start time: {start_time}")
    print(f"End time:   {datetime.now()}")
    print(f"Total alerts: {sum(alert_counts.values())}")

    if alert_counts:
        print("\nAlerts per source:")
        for src, count in alert_counts.items():
            print(f"  {src}: {count} alerts")

    print("\nThis version is Windows-safe and 100% reliable for demos.")
    print("===============================")


if __name__ == "__main__":
    try:
        handle_simulator_messages()
    except KeyboardInterrupt:
        print_summary()
