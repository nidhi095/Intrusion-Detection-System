import socket, time

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
for i in range(40):
    sock.sendto(b"SIMULATED SYN FLOOD", ("127.0.0.1", 9999))
    time.sleep(0.02)

print("SYN flood simulation complete.")
