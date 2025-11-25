# main.py
from scapy.all import sniff, IP, TCP, UDP
from detector import detect_port_scan, detect_syn_flood, detect_invalid_ip
from logger import log_packet, init_log

import sys
import signal

print("🚀 Starting Intrusion Detection System...")
print("Monitoring live traffic. Press Ctrl + C to stop.\n")

# ensure log exists
init_log()

def analyze_packet(packet):
    try:
        if not packet.haslayer(IP):
            return

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        if packet.haslayer(TCP):
            protocol = "TCP"
            sport = getattr(packet[TCP], "sport", None)
            dport = getattr(packet[TCP], "dport", None)
            flags = packet.sprintf("%TCP.flags%")  # e.g. 'S', 'SA', 'A'
        elif packet.haslayer(UDP):
            protocol = "UDP"
            sport = getattr(packet[UDP], "sport", None)
            dport = getattr(packet[UDP], "dport", None)
            flags = None
        else:
            protocol = "OTHER"
            sport = None
            dport = None
            flags = None

        # Log every packet (non-blocking-ish)
        log_packet(src_ip, dst_ip, protocol, sport, dport)

        # Run detection checks
        alerts = []
        alerts.append(detect_port_scan(src_ip, dport))
        if protocol == "TCP":
            alerts.append(detect_syn_flood(src_ip, flags))
        alerts.append(detect_invalid_ip(src_ip))

        # Print alerts (if any)
        for alert in alerts:
            if alert:
                print(alert)
    except Exception as e:
        # keep the sniffer running even if one packet causes an error
        print(f"[{e.__class__.__name__}] {e}", file=sys.stderr)

def sigint_handler(sig, frame):
    print("\nStopping IDS... Bye.")
    sys.exit(0)

if __name__ == "__main__":
    # handle Ctrl+C gracefully
    signal.signal(signal.SIGINT, sigint_handler)
    # sniff on the default interface. If you need a specific interface, add iface="eth0" or similar.
    sniff(prn=analyze_packet, store=False)
