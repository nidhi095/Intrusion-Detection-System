# simulate_dns_flood.py
"""
UDP/DNS-like flood simulator.
- Accepts target IP via CLI arg or prompt.
- Sends small number of DNS query-like UDP packets to port 53.
SAFETY: Do NOT target public DNS servers.
"""

import sys
import time
from scapy.all import IP, UDP, DNS, DNSQR, send

def get_target(default="127.0.0.1"):
    if len(sys.argv) > 1:
        return sys.argv[1]
    t = input(f"Target IP for DNS flood (default {default}): ").strip()
    return t if t else default

def main():
    target = get_target()
    print("Simulating DNS-like UDP flood against", target)
    try:
        for _ in range(60):
            pkt = IP(dst=target)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname="example.com"))
            send(pkt, verbose=False)
            time.sleep(0.02)
        print("DNS flood simulation complete.")
    except PermissionError:
        print("Permission error: run with admin privileges or test on loopback.")
    except Exception as e:
        print("Error during DNS flood:", e)

if __name__ == "__main__":
    main()
