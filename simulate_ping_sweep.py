from scapy.all import IP, ICMP, send
import time

target_prefix = "192.168.31."   # adjust to your LAN prefix

print("🌐 Simulating ICMP Ping Sweep...")

for host in range(1, 60):  # ping .1 to .59
    dst = f"{target_prefix}{host}"
    packet = IP(dst=dst)/ICMP(type=8)  # Echo Request
    send(packet, verbose=False)
    time.sleep(0.02)  # small delay to avoid going too crazy

print("✅ ICMP ping sweep simulation complete.")
