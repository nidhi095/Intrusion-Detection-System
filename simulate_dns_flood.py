import socket
import time

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

for i in range(50):  # 50 flood packets
    message = "SIMULATED DNS FLOOD"
    sock.sendto(message.encode(), ("127.0.0.1", 9999))
    time.sleep(0.03)

print("DNS flood simulation complete.")
