import socket
import time
import random

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server = ('198.7.0.2', 10000)
sock.connect(server)
print(f"Conectat la {server}")

mesaje = ["salut", "ce faci?", "mesaj secret", "test 123", "hello world"]

while True:
    msg = random.choice(mesaje)
    sock.send(msg.encode())
    print(f"Trimis: {msg}")
    data = sock.recv(1024)
    print(f"Primit: {data.decode()}")
    time.sleep(2)

