import socket
import struct
import base64
import hashlib
import sys

SERVER = '207.154.223.90'
PORT = 53
SUBDOMAIN = 'tunel.turu2anapoi.app'

def construieste_query(tid, nume, qtype=16):
    header = struct.pack('!HHHHHH', tid, 0x0100, 1, 0, 0, 0)
    q = b''
    for e in nume.rstrip('.').split('.'):
        b = e.encode('ascii', errors='ignore')
        q += struct.pack('!B', len(b)) + b
    q += b'\x00' + struct.pack('!HH', qtype, 1)
    return header + q

def parseaza_raspuns(date):
    if len(date) < 12:
        return None
    nr = struct.unpack('!H', date[6:8])[0]
    poz = 12
    while poz < len(date) and date[poz] != 0:
        poz += date[poz] + 1
    poz += 5
    for _ in range(nr):
        if poz + 12 > len(date):
            break
        if date[poz:poz+2] == b'\xc0\x0c':
            poz += 2
        else:
            while date[poz] != 0:
                poz += date[poz] + 1
            poz += 1
        tip = struct.unpack('!H', date[poz:poz+2])[0]
        poz += 8
        lg = struct.unpack('!H', date[poz:poz+2])[0]
        poz += 2
        if tip == 16 and poz + lg <= len(date):
            txt_lg = date[poz]
            poz += 1
            txt = date[poz:poz+txt_lg].decode('ascii', errors='ignore')
            return txt
        poz += lg
    return None

def descarca(fisier):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3)
    tid = 0x1234

    nume = f'GET.{fisier}.{SUBDOMAIN}'
    q = construieste_query(tid, nume, 16)
    sock.sendto(q, (SERVER, PORT))

    bucati = {}
    total = -1

    while True:
        try:
            data, _ = sock.recvfrom(4096)
        except socket.timeout:
            print("Timeout")
            break

        txt = parseaza_raspuns(data)
        if not txt:
            continue
        if txt == 'DONE':
            break

        try:
            meta, b64 = txt.split(':', 1)
            i, t = meta.split('/')
            i, t = int(i), int(t)
            total = t
            if i not in bucati:
                bucati[i] = b64
                print(f"Primit {i+1}/{t}")

            ack_nume = f'ACK.{i}.{SUBDOMAIN}'
            ack = construieste_query(tid, ack_nume, 1)
            sock.sendto(ack, (SERVER, PORT))
        except Exception:
            continue

    if total == -1 or len(bucati) != total:
        print(f"Eroare: primite {len(bucati)}/{total} bucati")
        return

    text = ''.join(bucati[i] for i in range(total))
    date = base64.b64decode(text)

    with open(fisier, 'wb') as f:
        f.write(date)

    md5 = hashlib.md5(date).hexdigest()
    print(f"Fisier salvat: {fisier}")
    print(f"MD5: {md5}")
    print(f"Marime: {len(date)} bytes")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Folosire: python3 dns_tunnel_client.py <nume_fisier>")
        sys.exit(1)
    descarca(sys.argv[1])
