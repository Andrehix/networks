import socket
import struct
import threading
import time
import os
import logging
import json
import base64
import urllib.request
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from socketserver import ThreadingMixIn
from scapy.all import DNS, DNSRR
from dns_stats import gaseste_compania

class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True

logging.basicConfig(format='[%(asctime)s] %(levelname)s: %(message)s', level=logging.INFO)
logger = logging.getLogger(__name__)

PORT_DNS = 53
PORT_DOH = 8080
FISIER_BLACKLIST = os.path.join(os.path.dirname(__file__), 'blacklist.txt')
FISIER_LOG = os.path.join(os.path.dirname(__file__), 'domenii_blocate.txt')
DNS_UPSTREAM = '8.8.8.8'
IP_BLOCAT = '0.0.0.0'

lista_neagra = set()
log_blocari = []
log_lock = threading.Lock()
cache_dns = {}
cache_lock = threading.Lock()
TTL_CACHE = 300


def descarca_blacklist():
    urluri = [
        'https://raw.githubusercontent.com/anudeepND/blacklist/master/adservers.txt',
        'https://raw.githubusercontent.com/anudeepND/blacklist/master/Facebook.txt',
        'https://raw.githubusercontent.com/anudeepND/blacklist/master/CoinMiner.txt',
    ]
    domenii = set()
    for url in urluri:
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=30) as raspuns:
                for linie in raspuns.read().decode('utf-8').splitlines():
                    linie = linie.strip()
                    if linie and not linie.startswith('#'):
                        domenii.add(linie.split()[-1].lower())
        except Exception as e:
            logger.warning(f"Descarcare esuata {url}: {e}")
    with open(FISIER_BLACKLIST, 'w') as f:
        for d in sorted(domenii):
            f.write(f"{d}\n")
    return domenii


def incarca_blacklist():
    global lista_neagra
    if not os.path.exists(FISIER_BLACKLIST) or os.path.getsize(FISIER_BLACKLIST) == 0:
        lista_neagra = descarca_blacklist()
    else:
        with open(FISIER_BLACKLIST, 'r') as f:
            lista_neagra = {linie.strip().lower() for linie in f if linie.strip()}
    logger.info(f"Blacklist: {len(lista_neagra)} domenii")


def e_blocat(nume):
    nume = nume.lower().rstrip('.')
    if nume in lista_neagra:
        return True
    bucati = nume.split('.')
    for i in range(1, len(bucati)):
        if '.'.join(bucati[i:]) in lista_neagra:
            return True
    return False


def parseaza_nume_dns(date):
    if len(date) < 12:
        return None, None
    pozitie = 12
    etichete = []
    while pozitie < len(date):
        lungime = date[pozitie]
        if lungime == 0:
            pozitie += 1
            break
        pozitie += 1
        if pozitie + lungime > len(date):
            return None, None
        etichete.append(date[pozitie:pozitie+lungime].decode('ascii', errors='ignore'))
        pozitie += lungime
    return '.'.join(etichete), pozitie


def construieste_raspuns_blocat(date_brute):
    # raspuns DNS care indica IP_BLOCAT, dupa modelul Micro DNS Server din capitolul6
    cerere = DNS(date_brute)
    raspuns = DNS(id=cerere.id, qr=1, aa=0, rd=cerere.rd, ra=1,
                  qd=cerere.qd,
                  an=DNSRR(rrname=cerere.qd.qname, type='A', ttl=30, rdata=IP_BLOCAT))
    return bytes(raspuns)


def forward_raw(date_brute):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        sock.sendto(date_brute, (DNS_UPSTREAM, 53))
        raspuns, _ = sock.recvfrom(4096)
        sock.close()
        tid = struct.unpack('!H', date_brute[0:2])[0]
        return struct.pack('!H', tid) + raspuns[2:]
    except Exception:
        return None


def logheaza_blocare(nume):
    with log_lock:
        log_blocari.append((nume, time.time()))
        with open(FISIER_LOG, 'a') as f:
            f.write(f"{nume}\n")


def server_dns():
    incarca_blacklist()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('0.0.0.0', PORT_DNS))
    logger.info(f"DNS pe UDP:{PORT_DNS}")
    while True:
        date, adresa = sock.recvfrom(4096)
        nume, _ = parseaza_nume_dns(date)
        tid = struct.unpack('!H', date[0:2])[0]
        if not nume:
            continue
        logger.info(f"Cerere: {nume}")
        if e_blocat(nume):
            logger.info(f"BLOCAT: {nume}")
            logheaza_blocare(nume)
            raspuns = construieste_raspuns_blocat(date)
        else:
            with cache_lock:
                cached = cache_dns.get(nume)
                if cached and time.time() < cached[1]:
                    raspuns = struct.pack('!H', tid) + cached[0][2:]
                    logger.info(f"CACHE: {nume}")
                    sock.sendto(raspuns, adresa)
                    continue
            raspuns = forward_raw(date)
            if raspuns:
                logger.info(f"REZOLVAT: {nume}")
                with cache_lock:
                    cache_dns[nume] = (raspuns, time.time() + TTL_CACHE)
            else:
                logger.warning(f"ESUAT: {nume}")
                raspuns = construieste_raspuns_blocat(date)
        sock.sendto(raspuns, adresa)


class DoH(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == '/dns-query' or parsed.path == '/rezolva':
            params = parse_qs(parsed.query)
            dns_b64 = params.get('dns', [None])[0]
            if dns_b64:
                try:
                    self.raspunde_binar(base64.urlsafe_b64decode(dns_b64 + '==='))
                    return
                except Exception:
                    pass
            nume = params.get('name', [None])[0]
            if nume:
                self.raspunde_json(nume)
                return
            self.send_error(400)
        elif parsed.path == '/statistici':
            self.pagina_statistici()
        elif parsed.path == '/':
            self.send_html('<h1>DNS AdBlocker</h1><p><a href="/statistici">Statistici</a></p>')
        else:
            self.send_error(404)

    def do_POST(self):
        corp = self.rfile.read(int(self.headers.get('Content-Length', 0)))
        if corp and corp[0:1] != b'{':
            self.raspunde_binar(corp)
        else:
            try:
                self.raspunde_json(json.loads(corp).get('name', ''))
            except Exception:
                self.send_error(400)

    def raspunde_binar(self, date):
        nume, _ = parseaza_nume_dns(date)
        tid = struct.unpack('!H', date[0:2])[0]
        if not nume:
            self.send_error(400)
            return
        logger.info(f"DoH: {nume}")
        if e_blocat(nume):
            logheaza_blocare(nume)
            raspuns = construieste_raspuns_blocat(date)
        else:
            gasit = False
            with cache_lock:
                cached = cache_dns.get(nume)
                if cached and time.time() < cached[1]:
                    raspuns = struct.pack('!H', tid) + cached[0][2:]
                    gasit = True
            if not gasit:
                raspuns = forward_raw(date)
                if raspuns:
                    with cache_lock:
                        cache_dns[nume] = (raspuns, time.time() + TTL_CACHE)
                else:
                    raspuns = construieste_raspuns_blocat(date)
        self.send_response(200)
        self.send_header('Content-Type', 'application/dns-message')
        self.send_header('Content-Length', str(len(raspuns)))
        self.end_headers()
        self.wfile.write(raspuns)

    def raspunde_json(self, nume):
        raspuns = {'Status': 0, 'TC': False, 'RD': True, 'RA': True, 'AD': False, 'CD': False, 'Question': [{'name': nume, 'type': 1}]}
        if e_blocat(nume):
            logheaza_blocare(nume)
            raspuns['Answer'] = [{'name': nume, 'type': 1, 'TTL': 30, 'data': IP_BLOCAT}]
        else:
            raw = forward_raw(struct.pack('!HHHHHH', 0x4242, 0x0100, 1, 0, 0, 0) + b'\x00\x00\x01\x00\x01')
            if raw:
                raspuns['Answer'] = [{'name': nume, 'type': 1, 'TTL': 300, 'data': '0.0.0.0'}]
            else:
                raspuns['Answer'] = []
        self.send_response(200)
        self.send_header('Content-Type', 'application/dns-json')
        self.end_headers()
        self.wfile.write(json.dumps(raspuns).encode())

    def pagina_statistici(self):
        with log_lock:
            total = len(log_blocari)
            contor_companii = {}
            contor_domenii = {}
            for domeniu, _ in log_blocari:
                contor_domenii[domeniu] = contor_domenii.get(domeniu, 0) + 1
                companie = gaseste_compania(domeniu)
                if companie:
                    contor_companii[companie] = contor_companii.get(companie, 0) + 1
            sortate_companii = sorted(contor_companii.items(), key=lambda x: x[1], reverse=True)
            sortate_domenii = sorted(contor_domenii.items(), key=lambda x: x[1], reverse=True)[:30]
            clasificate = sum(contor_companii.values())

        html = f"""<html><head><title>Statistici DNS</title>
        <style>
            body{{font-family:sans-serif;max-width:900px;margin:30px auto;padding:20px;background:#1a1a2e;color:#eee}}
            h1{{color:#4CAF50}}h2{{color:#81c784;margin-top:30px}}
            .card{{background:#16213e;border-radius:10px;padding:20px;margin:15px 0}}
            table{{border-collapse:collapse;width:100%}}
            th,td{{border:1px solid #333;padding:8px 12px;text-align:left}}
            th{{background:#0f3460;color:#4CAF50}}tr:nth-child(even){{background:#1a1a3e}}
            .big{{font-size:48px;color:#4CAF50;font-weight:bold}}
        </style></head><body>
        <h1>Statistici DNS AdBlocker</h1>
        <div class="card"><span class="big">{total}</span><p>cereri blocate in total</p></div>
        <div class="card"><p>Clasificate pe companii: <b>{clasificate}</b> ({clasificate*100//total if total else 0}%)<br>Necunoscute: <b>{total-clasificate}</b> ({(total-clasificate)*100//total if total else 0}%)</p></div>
        <h2>Blocari pe companii</h2>
        <div class="card"><table><tr><th>Companie</th><th>Blocari</th><th>%</th></tr>"""
        for companie, nr in sortate_companii:
            html += f"<tr><td>{companie}</td><td>{nr}</td><td>{nr*100//total if total else 0}%</td></tr>"
        html += "</table></div>"
        html += "<h2>Top 30 domenii blocate</h2><div class='card'><table><tr><th>Domeniu</th><th>Blocari</th></tr>"
        for domeniu, nr in sortate_domenii:
            html += f"<tr><td>{domeniu}</td><td>{nr}</td></tr>"
        html += "</table></div></body></html>"
        self.send_html(html)

    def send_html(self, html):
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        self.wfile.write(html.encode())

    def log_message(self, *args):
        pass


if __name__ == '__main__':
    threading.Thread(target=server_dns, daemon=True).start()
    srv = ThreadingHTTPServer(('0.0.0.0', PORT_DOH), DoH)
    logger.info(f"DoH pe TCP:{PORT_DOH}")
    srv.serve_forever()