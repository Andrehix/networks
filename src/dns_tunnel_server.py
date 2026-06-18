import socket
import struct
import base64
import os

PORT = 53
SUBDOMAIN = "tunel.turu2anapoi.app"
FISIERE = "/root/fisiere_tunel"

def parseaza_nume(date):
    if len(date) < 12:
        return None
    tid = struct.unpack('!H', date[0:2])[0]
    poz = 12
    etichete = []
    while poz < len(date):
        lg = date[poz]
        if lg == 0:
            poz += 1
            break
        poz += 1
        etichete.append(date[poz:poz+lg].decode('ascii', errors='ignore'))
        poz += lg
    qtype = struct.unpack('!H', date[poz:poz+2])[0] if poz+2 <= len(date) else 0
    return tid, '.'.join(etichete), qtype

def construieste_txt(tid, nume, text):
    header = struct.pack('!HHHHHH', tid, 0x8180, 1, 1, 0, 0)
    q = b''
    for e in nume.rstrip('.').split('.'):
        b = e.encode('ascii', errors='ignore')
        q += struct.pack('!B', len(b)) + b
    q += b'\x00' + struct.pack('!HH', 16, 1)
    text_b = text.encode('utf-8')
    rr = b'\xc0\x0c\x00\x10\x00\x01\x00\x00\x00\x1e'
    rr += struct.pack('!H', len(text_b) + 1)
    rr += struct.pack('!B', len(text_b)) + text_b
    return header + q + rr

def construieste_a(tid, nume, ip):
    header = struct.pack('!HHHHHH', tid, 0x8180, 1, 1, 0, 0)
    q = b''
    for e in nume.rstrip('.').split('.'):
        b = e.encode('ascii', errors='ignore')
        q += struct.pack('!B', len(b)) + b
    q += b'\x00' + struct.pack('!HH', 1, 1)
    rr = b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x1e\x00\x04'
    rr += struct.pack('BBBB', *[int(p) for p in ip.split('.')])
    return header + q + rr

def imparte_fisier(cale):
    with open(cale, 'rb') as f:
        date = f.read()
    b64 = base64.b64encode(date).decode('ascii')
    bucati = []
    for i in range(0, len(b64), 200):
        bucati.append(b64[i:i+200])
    return bucati

def server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('0.0.0.0', PORT))
    print(f"Server tunel DNS pe portul {PORT}")

    os.makedirs(FISIERE, exist_ok=True)

    while True:
        date, adresa = sock.recvfrom(4096)
        rez = parseaza_nume(date)
        if not rez:
            continue
        tid, nume, qtype = rez

        if not nume.endswith('.' + SUBDOMAIN):
            continue

        prefix = nume.replace('.' + SUBDOMAIN, '')

        if prefix.startswith('GET.'):
            fisier = prefix[4:]
            cale = os.path.join(FISIERE, fisier)
            if not os.path.exists(cale):
                r = construieste_a(tid, nume, '0.0.0.0')
                sock.sendto(r, adresa)
                continue

            bucati = imparte_fisier(cale)
            total = len(bucati)
            print(f"Trimit {fisier}: {total} bucati")

            for i, buc in enumerate(bucati):
                payload = f"{i}/{total}:{buc}"
                r = construieste_txt(tid, nume, payload)
                sock.sendto(r, adresa)

                sock.settimeout(2)
                for _ in range(3):
                    try:
                        ack_data, _ = sock.recvfrom(512)
                        _, ack_nume, _ = parseaza_nume(ack_data)
                        if ack_nume and ack_nume.startswith(f'ACK.{i}.'):
                            break
                    except socket.timeout:
                        sock.sendto(r, adresa)
                sock.settimeout(None)

            r = construieste_txt(tid, nume, "DONE")
            sock.sendto(r, adresa)
            print(f"Fisier {fisier} trimis complet")

if __name__ == '__main__':
    server()
