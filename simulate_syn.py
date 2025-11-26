import socket
import time

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

for i in range(50):
    msg = "SYN FLOOD ATTEMPT"
    sock.sendto(msg.encode(), ("127.0.0.1", 9999))
    time.sleep(0.02)

print("SYN flood simulation complete.")
