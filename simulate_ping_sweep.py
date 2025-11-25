# simulate_ping_sweep.py
"""
ICMP ping sweep simulator.
- Accepts a target IP or prefix via CLI arg or input.
- If a prefix ending with '.' is given (e.g. 192.168.1.), it sweeps hosts 1..30.
- If a single IP is provided, it repeatedly pings that host.
SAFETY: Use 127.0.0.1 or an isolated test network.
"""

import sys
import time
from scapy.all import IP, ICMP, send

def get_target(default="127.0.0.1"):
    if len(sys.argv) > 1:
        return sys.argv[1]
    t = input(f"Target IP or prefix (e.g. 127.0.0.1 or 192.168.31.): default {default}: ").strip()
    return t if t else default

def main():
    target = get_target()
    print("Simulating ICMP ping sweep against", target)
    try:
        if target.endswith("."):
            # prefix sweep
            for host in range(1, 31):
                dst = f"{target}{host}"
                send(IP(dst=dst)/ICMP(type=8), verbose=False)
                time.sleep(0.02)
        else:
            # single IP multiple pings
            for _ in range(30):
                send(IP(dst=target)/ICMP(type=8), verbose=False)
                time.sleep(0.02)
        print("Ping sweep simulation complete.")
    except PermissionError:
        print("Permission error: run with admin privileges or test on loopback.")
    except Exception as e:
        print("Error during ping sweep:", e)

if __name__ == "__main__":
    main()
