# simulate_port_scan.py
"""
TCP SYN port scan simulator.
- Accepts target IP via CLI arg or interactive prompt.
- Sends SYN packets to a range of ports (configurable within script).
SAFETY: Only run against 127.0.0.1 or an isolated test machine.
"""

import sys
import time
from scapy.all import IP, TCP, send

def get_target(default="127.0.0.1"):
    # CLI arg preferred
    if len(sys.argv) > 1:
        return sys.argv[1]
    t = input(f"Target IP for port scan (default {default}): ").strip()
    return t if t else default

def main():
    target = get_target()
    print(f"Simulating TCP SYN port scan against {target} (safe default ports).")
    try:
        # safe default: small range
        for port in range(20, 81):
            pkt = IP(dst=target)/TCP(dport=port, flags="S")
            send(pkt, verbose=False)
            time.sleep(0.01)
        print("Port scan simulation complete.")
    except PermissionError:
        print("Permission error: run with admin privileges or test on loopback.")
    except Exception as e:
        print("Error during port scan:", e)

if __name__ == "__main__":
    main()
