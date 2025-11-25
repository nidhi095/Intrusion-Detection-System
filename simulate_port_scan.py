# simulate_port_scan.py
from scapy.all import IP, TCP, send
import time

target_ip = "127.0.0.1"  # adjust
print("🔎 Simulating port scan...")
for port in range(20, 200):
    pkt = IP(dst=target_ip)/TCP(dport=port, flags="S")
    send(pkt, verbose=False)
    time.sleep(0.01)
print("✅ Port scan done")
