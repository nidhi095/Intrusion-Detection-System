# Intrusion Detection System (Simplified; no menu)

This repo contains a small educational IDS and a set of simulation scripts.

## Files
- `main.py`: sniffer + detectors. Optionally accepts an IP argument to focus on a specific host.
- `detector.py`: detection logic (port scan, SYN flood, ping sweep, etc.).
- `logger.py`: logs captured packets to `logs/traffic_log.csv`.
- `simulate_port_scan.py`: TCP SYN port-scan simulator (accepts target IP).
- `simulate_ping_sweep.py`: ICMP ping sweep simulator (accepts IP or prefix).
- `simulate_syn.py`: SYN flood simulator (accepts target IP).
- `simulate_dns_flood.py`: UDP DNS-like flood simulator (accepts target IP).
- `requirements.txt`: packages to install.

## Safety
**Always** use `127.0.0.1` (loopback) or an isolated test network for simulations. Do **not** target public IPs.

## How to run
1. Install dependencies:
pip install -r requirements.txt

markdown
Copy code
2. Start the sniffer:
python main.py # or python main.py 127.0.0.1 to focus on loopback

arduino
Copy code
3. In another terminal run a simulator:
python simulate_port_scan.py 127.0.0.1
python simulate_ping_sweep.py 127.0.0.1
python simulate_syn.py 127.0.0.1
python simulate_dns_flood.py 127.0.0.1

vbnet
Copy code
4. Stop the sniffer with Ctrl+C to see the summary; logs are in `logs/traffic_log.csv`.

## Notes for Windows users
- Install Npcap and run Python as administrator to sniff non-loopback interfaces.