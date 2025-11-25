# main.py
from scapy.all import sniff, IP, TCP, UDP, ICMP
from detector import (
    detect_port_scan,
    detect_syn_flood,
    detect_invalid_ip,
    detect_ping_sweep,   # <- make sure this exists in detector.py
)
from logger import log_packet, init_log

import sys
import signal
from collections import defaultdict

print("🚀 Starting Intrusion Detection System...")
print("Monitoring live traffic. Press Ctrl + C to stop.\n")

# ensure log exists
init_log()

# Stats
packet_count = 0
packets_per_ip = defaultdict(int)
alerts_per_ip = defaultdict(int)


def analyze_packet(packet):
    global packet_count, packets_per_ip, alerts_per_ip

    try:
        # Only process IP packets
        if not packet.haslayer(IP):
            return

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        # Basic stats
        packet_count += 1
        packets_per_ip[src_ip] += 1

        protocol = "OTHER"
        sport = None
        dport = None
        flags = None
        icmp_type = None

        # Identify protocol & extract fields
        if packet.haslayer(TCP):
            protocol = "TCP"
            sport = getattr(packet[TCP], "sport", None)
            dport = getattr(packet[TCP], "dport", None)
            flags = packet.sprintf("%TCP.flags%")
        elif packet.haslayer(UDP):
            protocol = "UDP"
            sport = getattr(packet[UDP], "sport", None)
            dport = getattr(packet[UDP], "dport", None)
        elif packet.haslayer(ICMP):
            protocol = "ICMP"
            icmp_type = getattr(packet[ICMP], "type", None)

        # Log packet (to CSV)
        log_packet(src_ip, dst_ip, protocol, sport, dport)

        # Run detection checks
        alerts = []

        # Port scan detection (uses destination port)
        alerts.append(detect_port_scan(src_ip, dport))

        # SYN flood detection (only for TCP)
        if protocol == "TCP":
            alerts.append(detect_syn_flood(src_ip, flags))

        # ICMP ping sweep detection
        if protocol == "ICMP":
            alerts.append(detect_ping_sweep(src_ip, dst_ip, icmp_type))

        # Demo: private/internal IP flag
        alerts.append(detect_invalid_ip(src_ip))

        # Print alerts (if any) & increment alert counter
        for alert in alerts:
            if alert:
                print(alert)
                alerts_per_ip[src_ip] += 1

    except Exception as e:
        # keep the sniffer running even if one packet causes an error
        print(f"[{e.__class__.__name__}] {e}", file=sys.stderr)


def sigint_handler(sig, frame):
    from operator import itemgetter
    global packet_count, packets_per_ip, alerts_per_ip

    print("\n\n================ IDS SUMMARY ================")
    print(f"Total packets captured: {packet_count}")
    print(f"Unique source IPs seen: {len(packets_per_ip)}\n")

    # Top talkers
    if packets_per_ip:
        print("Top talkers (by packet count):")
        for ip, count in sorted(packets_per_ip.items(), key=itemgetter(1), reverse=True)[:5]:
            print(f"  {ip}: {count} packets")

    # Alerts
    if alerts_per_ip:
        print("\nIPs that triggered alerts:")
        for ip, count in sorted(alerts_per_ip.items(), key=itemgetter(1), reverse=True):
            print(f"  {ip}: {count} alerts")
    else:
        print("\nNo alerts were generated.")

    print("\n=============================================")
    print("Stopping IDS... Bye.")
    sys.exit(0)


if __name__ == "__main__":
    # handle Ctrl+C gracefully
    signal.signal(signal.SIGINT, sigint_handler)
    # sniff on the default interface. If you need a specific interface, add iface="eth0" or similar.
    sniff(prn=analyze_packet, store=False)
