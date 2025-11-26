import socket
import time

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

for i in range(1, 21):   # sweep 20 hosts
    message = f"SIMULATED PING SWEEP -> 192.168.1.{i}"
    sock.sendto(message.encode(), ("127.0.0.1", 9999))
    time.sleep(0.05)

print("Ping sweep simulation complete.")
