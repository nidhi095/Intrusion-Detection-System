# simulate_dns_flood.py
from scapy.all import IP, UDP, DNS, DNSQR, send
import time

target_ip = "8.8.8.8"  # public DNS, avoid heavy traffic; prefer local DNS in lab
print("⚠️ Simulating many DNS queries (use small counts in real network tests)...")
for _ in range(100):
    pkt = IP(dst=target_ip)/UDP(sport=12345, dport=53)/DNS(rd=1, qd=DNSQR(qname="example.com"))
    send(pkt, verbose=False)
    time.sleep(0.02)
print("✅ DNS flood sim done")
