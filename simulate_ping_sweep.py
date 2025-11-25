# simulate_ping_sweep.py
from scapy.all import IP, ICMP, send
import time

target_prefix = "192.168.31."  # change to your LAN prefix

print("🌐 Simulating ICMP Ping Sweep...")
for host in range(1, 80):
    dst = f"{target_prefix}{host}"
    pkt = IP(dst=dst)/ICMP(type=8)
    send(pkt, verbose=False)
    time.sleep(0.02)
print("✅ Ping sweep done")
