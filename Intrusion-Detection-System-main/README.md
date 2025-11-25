# Lightweight Intrusion Detection System (IDS)

## What it is
A simple Python IDS that sniffs live packets (via Scapy), logs traffic to CSV, and detects basic suspicious activity:
- Port scan detection
- SYN flood detection
- Flags private IP usage (for demo)

## Files
- `main.py`        : main sniffer + detector runner
- `detector.py`    : detection logic
- `logger.py`      : CSV logging
- `simulate_attack.py` : simple port-scan simulator (run while IDS running)
- `simulate_syn.py`     : SYN flood simulator (run while IDS running)
- `requirements.txt`

## Quick start
1. Create a virtualenv (optional):
   ```bash
   python -m venv venv
   source venv/bin/activate   # macOS/Linux
   venv\Scripts\activate      # Windows
