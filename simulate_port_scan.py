import socket, time

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
for p in range(1, 50):
    sock.sendto(f"SIMULATED PORT SCAN port {p}".encode(), ("127.0.0.1", 9999))
    time.sleep(0.03)

print("Port scan simulation complete.")
