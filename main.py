# HYBRID IDS: Real Scapy Sniffer + UDP-based Simulation Listener
# Fully compatible with Windows and your detection logic

import sys
import signal
import socket
import threading
from datetime import datetime
from collections import defaultdict
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

# =========================
# GLOBALS
# =========================
packet_count = 0
alerts_per_ip = defaultdict(int)
packets_per_ip = defaultdict(int)
protocol_counter = defaultdict(int)
start_time = datetime.now()

EVENT_QUEUE = []  # unified event buffer


# =========================
# PRINT ALERT
# =========================
def push_alert(msg, src="SIMULATION"):
    EVENT_QUEUE.append((src, msg))
    print(f"[ALERT] {msg} (from {src})")
    alerts_per_ip[src] += 1


# =========================
# REAL PACKET ANALYZER
# =========================
def analyze_packet(packet):
    global packet_count

    try:
        if not packet.haslayer(IP):
            return

        src = packet[IP].src
        dst = packet[IP].dst
        packet_count += 1
        packets_per_ip[src] += 1

        protocol = "OTHER"
        sport = dport = flags = icmp_type = None

        if packet.haslayer(TCP):
            protocol = "TCP"
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            flags = packet.sprintf("%TCP.flags%")

        elif packet.haslayer(UDP):
            protocol = "UDP"
            sport = packet[UDP].sport
            dport = packet[UDP].dport

        elif packet.haslayer(ICMP):
            protocol = "ICMP"
            icmp_type = packet[ICMP].type

        protocol_counter[protocol] += 1

        # Log
        try:
            log_packet(src, dst, protocol, sport, dport)
        except:
            pass

        # Run detectors
        detectors = [
            detect_port_scan(src, dport),
            detect_invalid_ip(src),
            detect_packet_rate(src),
        ]

        if protocol == "TCP":
            detectors.append(detect_syn_flood(src, flags))
            detectors.append(detect_half_open_handshakes(src, flags))

        if protocol == "ICMP":
            detectors.append(detect_ping_sweep(src, dst, icmp_type))

        for alert in detectors:
            if alert:
                push_alert(alert, src)

    except Exception as e:
        print("[ERROR]", e)


# =========================
# SIMULATION LISTENER (UDP)
# =========================
def simulation_listener():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 9999))

    print("[*] Simulation listener active (port 9999)\n")

    while True:
        msg, addr = sock.recvfrom(2048)
        text = msg.decode().strip()
        push_alert(text, src=addr[0])


# =========================
# SUMMARY
# =========================
def summary():
    print("\n=== IDS SUMMARY ===")
    print(f"Start: {start_time}")
    print(f"End:   {datetime.now()}")
    print(f"Packets captured: {packet_count}")
    print(f"Total alerts: {sum(alerts_per_ip.values())}")

    print("\nAlerts per IP:")
    for ip, cnt in alerts_per_ip.items():
        print(f"  {ip}: {cnt}")

    print(f"\nLog saved at: {LOG_PATH}")
    print("==========================")


# =========================
# MAIN
# =========================
if __name__ == "__main__":
    signal.signal(signal.SIGINT, lambda s, f: (summary(), sys.exit()))

    init_log()

    print("HYBRID IDS STARTED")
    print("[*] Real packet sniffer running...")
    print("[*] Simulation listener running (UDP port 9999)\n")

    # Start simulator listener thread
    threading.Thread(target=simulation_listener, daemon=True).start()

    # Start real packet sniffer
    sniff(prn=analyze_packet, store=False)
