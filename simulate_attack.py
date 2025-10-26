# simulate_attack.py
from scapy.all import IP, TCP, send
import time

# target can be 127.0.0.1 for local demo, or your machine's IP on LAN
target_ip = "127.0.0.1"

print("🧨 Simulating Port Scan against", target_ip)

# Simulate many destination ports from same source (port scan)
for port in range(20, 60):
    packet = IP(dst=target_ip)/TCP(dport=port, flags="S")
    send(packet, verbose=False)
    time.sleep(0.05)

print("✅ Port scan simulation complete.")
