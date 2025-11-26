import socket
import time

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

for i in range(40):
    msg = "DNS FLOOD ATTEMPT"
    sock.sendto(msg.encode(), ("127.0.0.1", 9999))
    time.sleep(0.03)

print("DNS flood simulation complete.")
