import socket
import time

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

for port in range(1, 30):
    msg = f"PORT SCAN DETECTED on port {port}"
    sock.sendto(msg.encode(), ("127.0.0.1", 9999))
    time.sleep(0.05)

print("Port scan simulation complete.")
