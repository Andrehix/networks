import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(('0.0.0.0', 10000))
sock.listen(5)
print("Server asculta pe portul 10000")

while True:
    conn, addr = sock.accept()
    print(f"Conectat: {addr}")
    while True:
        data = conn.recv(1024)
        if not data:
            break
        msg = data.decode()
        print(f"Primit: {msg}")
        raspuns = f"Server a primit: {msg}"
        conn.send(raspuns.encode())
    conn.close()
    print("Deconectat")

