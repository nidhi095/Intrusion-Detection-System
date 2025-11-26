import socket
import time

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

for i in range(10):
    msg = f"PING SWEEP ICMP request to 127.0.0.{i}"
    sock.sendto(msg.encode(), ("127.0.0.1", 9999))
    time.sleep(0.1)

print("Ping sweep simulation complete.")
