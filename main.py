# main.py
import sys
import signal
import threading
from collections import defaultdict
from scapy.all import sniff, IP, TCP, UDP, ICMP
from logger import init_log, log_packet
from detector import (
    detect_port_scan,
    detect_syn_flood,
    detect_half_open_handshakes,
    detect_ping_sweep,
    detect_packet_rate,
    detect_protocol_stats,
    detect_app_protocol,
    detect_dns_flood,
    detect_ttl_anomaly,
    reset_detectors_state,
)

# Global runtime flags (which detectors to run)
ENABLED = {
    "port_scan": True,
    "syn_flood": True,
    "half_open": True,
    "ping_sweep": True,
    "packet_rate": True,
    "protocol_stats": True,
    "app_protocol": True,
    "dns_flood": True,
    "ttl_anomaly": True,
}

# Runtime stats
packet_count = 0
packets_per_ip = defaultdict(int)
alerts_per_ip = defaultdict(int)
protocol_counter = defaultdict(int)

sniff_thread = None
stop_sniffing = threading.Event()

def analyze_packet(packet):
    global packet_count, packets_per_ip, alerts_per_ip, protocol_counter
    try:
        if not packet.haslayer(IP):
            return

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        packet_count += 1
        packets_per_ip[src_ip] += 1

        # determine protocol
        protocol = "OTHER"
        sport = None
        dport = None
        flags = None
        icmp_type = None
        ttl = getattr(packet[IP], "ttl", None)

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

        protocol_counter[protocol] += 1

        # Logging (append to csv)
        try:
            log_packet(src_ip, dst_ip, protocol, sport, dport)
        except Exception:
            pass

        # Run detectors based on flags
        alerts = []

        if ENABLED["port_scan"]:
            alerts.append(detect_port_scan(src_ip, dport))

        if ENABLED["syn_flood"] and protocol == "TCP":
            alerts.append(detect_syn_flood(src_ip, flags))

        if ENABLED["half_open"] and protocol == "TCP":
            alerts.append(detect_half_open_handshakes(src_ip, flags))

        if ENABLED["ping_sweep"] and protocol == "ICMP":
            alerts.append(detect_ping_sweep(src_ip, dst_ip, icmp_type))

        if ENABLED["packet_rate"]:
            alerts.append(detect_packet_rate(src_ip))

        if ENABLED["protocol_stats"]:
            # protocol stats detector returns None normally; run periodically if needed
            alerts.append(detect_protocol_stats(protocol_counter))

        if ENABLED["app_protocol"]:
            alerts.append(detect_app_protocol(src_ip, dst_ip, protocol, sport, dport))

        if ENABLED["dns_flood"] and protocol == "UDP" and dport == 53:
            alerts.append(detect_dns_flood(src_ip))

        if ENABLED["ttl_anomaly"]:
            alerts.append(detect_ttl_anomaly(src_ip, ttl))

        for alert in alerts:
            if alert:
                print(alert)
                # attempt to attribute to src_ip if available
                alerts_per_ip[src_ip] += 1

    except Exception as e:
        # keep running even if a packet causes an exception
        print(f"[{e.__class__.__name__}] {e}", file=sys.stderr)


def start_sniffer():
    stop_sniffing.clear()
    print("Starting sniffer... (Ctrl+C in this menu to stop via 'Stop sniffing')")

    def run_sniff():
        try:
            sniff(prn=analyze_packet, store=False, stop_filter=lambda pkt: stop_sniffing.is_set())
        except Exception as e:
            print(f"[SnifferError] {e}")

    global sniff_thread
    sniff_thread = threading.Thread(target=run_sniff, daemon=True)
    sniff_thread.start()

def stop_sniffer():
    stop_sniffing.set()
    if sniff_thread:
        sniff_thread.join(timeout=1)
    # reset detector internal counters if desired
    reset_detectors_state()
    print("Sniffer stopped.")

def print_summary():
    from operator import itemgetter
    print("\n\n================ IDS SUMMARY ================")
    print(f"Total packets captured: {packet_count}")
    print(f"Unique source IPs seen: {len(packets_per_ip)}\n")
    if packets_per_ip:
        print("Top talkers (by packet count):")
        for ip, count in sorted(packets_per_ip.items(), key=itemgetter(1), reverse=True)[:10]:
            print(f"  {ip}: {count} packets")
    if alerts_per_ip:
        print("\nIPs that triggered alerts:")
        for ip, count in sorted(alerts_per_ip.items(), key=itemgetter(1), reverse=True):
            print(f"  {ip}: {count} alerts")
    else:
        print("\nNo alerts were generated.")
    print("=============================================\n")

def toggle_feature(feature):
    if feature in ENABLED:
        ENABLED[feature] = not ENABLED[feature]
        print(f"{feature} set to {ENABLED[feature]}")
    else:
        print("Unknown feature:", feature)

def export_logs():
    print("Logs are in the logs/traffic_log.csv file (created by logger.py).")

def menu():
    init_log()
    while True:
        print("\n=== MINI IDS MENU ===")
        print("1. Start sniffing")
        print("2. Stop sniffing")
        print("3. Toggle detectors (show current status)")
        print("4. View runtime stats")
        print("5. Export logs / view log path")
        print("6. Reset detectors internal state")
        print("7. Exit")
        choice = input("Enter choice: ").strip()
        if choice == "1":
            start_sniffer()
        elif choice == "2":
            stop_sniffer()
        elif choice == "3":
            print("Detectors status:")
            for k, v in ENABLED.items():
                print(f"  {k}: {v}")
            f = input("Enter detector to toggle (exact name) or press Enter to go back: ").strip()
            if f:
                toggle_feature(f)
        elif choice == "4":
            print_summary()
            print("Protocol distribution so far:")
            for proto, cnt in protocol_counter.items():
                print(f"  {proto}: {cnt}")
        elif choice == "5":
            export_logs()
        elif choice == "6":
            reset_detectors_state()
            print("Detector internal state reset.")
        elif choice == "7":
            print("Exiting... stopping sniffer if running.")
            stop_sniffer()
            break
        else:
            print("Unknown choice. Try again.")

if __name__ == "__main__":
    try:
        menu()
    except KeyboardInterrupt:
        print("\nReceived Ctrl+C - exiting.")
        stop_sniffer()
        sys.exit(0)
