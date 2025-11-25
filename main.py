# main.py
"""
Simple menu-less IDS sniffer.
- Optionally accepts a target IP (CLI arg or input) to filter packet processing to that IP.
- Starts sniffing immediately and runs detectors on every packet.
- On Ctrl+C prints a short summary and exits.

Usage:
  python main.py                 # no IP filter (monitor all)
  python main.py 127.0.0.1      # only process packets with 127.0.0.1 as src or dst
"""

import sys
import signal
from collections import defaultdict
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP

from detector import (
    detect_port_scan,
    detect_syn_flood,
    detect_invalid_ip,
    detect_ping_sweep,
    detect_half_open_handshakes,
    detect_packet_rate,
)
from logger import init_log, log_packet, LOG_PATH

# Global runtime stats
packet_count = 0
packets_per_ip = defaultdict(int)
alerts_per_ip = defaultdict(int)
protocol_counter = defaultdict(int)

# Optional IP filter (process packets only if src or dst matches)
TARGET_IP = None
if len(sys.argv) > 1:
    TARGET_IP = sys.argv[1]
else:
    # interactive prompt if run without arg
    t = input("Enter an IP to focus on (press Enter to monitor all): ").strip()
    TARGET_IP = t if t else None

print("🚀 Starting Intrusion Detection System...")
if TARGET_IP:
    print(f"Monitoring packets involving IP: {TARGET_IP}")
else:
    print("Monitoring live traffic (no IP filter).")
print("Press Ctrl + C to stop.\n")

# ensure log exists
init_log()

def analyze_packet(packet):
    """
    Called for every captured packet. Extracts IP/TCP/UDP/ICMP pieces,
    logs packet, and runs detectors.
    """
    global packet_count, packets_per_ip, alerts_per_ip, protocol_counter

    try:
        if not packet.haslayer(IP):
            return

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        # If an IP filter is set, ignore packets not involving that IP.
        if TARGET_IP and TARGET_IP not in (src_ip, dst_ip):
            return

        packet_count += 1
        packets_per_ip[src_ip] += 1

        # Defaults
        protocol = "OTHER"
        sport = None
        dport = None
        flags = None
        icmp_type = None

        if packet.haslayer(TCP):
            protocol = "TCP"
            sport = getattr(packet[TCP], "sport", None)
            dport = getattr(packet[TCP], "dport", None)
            # Scapy returns flags as a string like 'S', 'SA', 'FA', etc.
            flags = packet.sprintf("%TCP.flags%")
        elif packet.haslayer(UDP):
            protocol = "UDP"
            sport = getattr(packet[UDP], "sport", None)
            dport = getattr(packet[UDP], "dport", None)
        elif packet.haslayer(ICMP):
            protocol = "ICMP"
            icmp_type = getattr(packet[ICMP], "type", None)

        protocol_counter[protocol] += 1

        # Try to log the packet - logging errors shouldn't stop sniffing
        try:
            log_packet(src_ip, dst_ip, protocol, sport, dport)
        except Exception:
            pass

        # Run detectors and collect alerts
        alerts = []
        alerts.append(detect_port_scan(src_ip, dport))
        if protocol == "TCP":
            alerts.append(detect_syn_flood(src_ip, flags))
            alerts.append(detect_half_open_handshakes(src_ip, flags))
        if protocol == "ICMP":
            alerts.append(detect_ping_sweep(src_ip, dst_ip, icmp_type))
        alerts.append(detect_invalid_ip(src_ip))
        alerts.append(detect_packet_rate(src_ip))

        for alert in alerts:
            if alert:
                print(alert)
                alerts_per_ip[src_ip] += 1

    except Exception as e:
        # keep sniffer alive if anything unexpected happens
        print(f"[{e.__class__.__name__}] {e}", file=sys.stderr)


def sigint_handler(sig, frame):
    """Gracefully stop on Ctrl+C and print a summary."""
    print("\n\nStopping IDS... Generating summary...\n")
    from operator import itemgetter

    print("=== IDS SUMMARY ===")
    print(f"Time: {datetime.now().isoformat()}")
    print(f"Total packets captured: {packet_count}")
    print(f"Unique source IPs: {len(packets_per_ip)}")
    if packets_per_ip:
        print("\nTop talkers:")
        for ip, cnt in sorted(packets_per_ip.items(), key=itemgetter(1), reverse=True)[:8]:
            print(f"  {ip}: {cnt} packets")
    if alerts_per_ip:
        print("\nIPs that triggered alerts:")
        for ip, cnt in sorted(alerts_per_ip.items(), key=itemgetter(1), reverse=True):
            print(f"  {ip}: {cnt} alerts")
    print(f"\nLog saved at: {LOG_PATH}")
    print("====================\n")
    sys.exit(0)


if __name__ == "__main__":
    # handle Ctrl+C gracefully
    signal.signal(signal.SIGINT, sigint_handler)
    # start sniffing on default interface; on Windows may require admin & Npcap
    sniff(prn=analyze_packet, store=False)
