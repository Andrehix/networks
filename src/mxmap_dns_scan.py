import json
import time
import os
import requests
from scapy.all import IP, UDP, DNS, DNSQR, sr1

DNS_SERVER  = "8.8.8.8"
INPUT_FILE  = "localitati_wikidata.json"
OUTPUT_FILE = "mxmap_data.json"
SAVE_EVERY  = 50


def dns_query(domeniu, qtype):
    pkt = IP(dst=DNS_SERVER) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=domeniu, qtype=qtype))
    try:
        resp = sr1(pkt, timeout=3, verbose=0)
    except Exception:
        return None
    if resp and resp.haslayer(DNS):
        return resp[DNS]
    return None


def get_mx(domeniu):
    dns = dns_query(domeniu, "MX")
    if not dns or dns.ancount == 0:
        return []
    records = []
    rr = dns.an
    while rr and hasattr(rr, "type"):
        if rr.type == 15:
            records.append({
                "prioritate": int(rr.pref),
                "host": rr.exchange.decode("ascii", errors="ignore").rstrip("."),
            })
        rr = rr.payload
    return sorted(records, key=lambda x: x["prioritate"])


def get_txt(domeniu):
    dns = dns_query(domeniu, "TXT")
    if not dns or dns.ancount == 0:
        return []
    records = []
    rr = dns.an
    while rr and hasattr(rr, "type"):
        if rr.type == 16:
            raw = rr.rdata
            if isinstance(raw, list):
                txt = b"".join(raw).decode("utf-8", errors="ignore")
            elif isinstance(raw, bytes):
                txt = raw.decode("utf-8", errors="ignore")
            else:
                txt = str(raw)
            records.append(txt)
        rr = rr.payload
    return records


def get_ip(hostname):
    dns = dns_query(hostname, "A")
    if not dns or dns.ancount == 0:
        return None
    rr = dns.an
    while rr and hasattr(rr, "type"):
        if rr.type == 1:
            return rr.rdata
        rr = rr.payload
    return None


def get_ip_info(ip):
    try:
        data = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5).json()
        return data.get("country"), data.get("org", "")
    except Exception:
        return None, ""


def classify(mx_records, txt_records, tara, domeniu=""):
    for mx in mx_records:
        host = mx["host"].lower()
        if "google" in host:
            return "google_us"
        if "outlook.com" in host or "onmicrosoft.com" in host:
            return "microsoft_us"
        if "yahoodns" in host:
            return "yahoo_us"

    for txt in txt_records:
        if "v=spf1" in txt:
            if "google.com" in txt:
                return "google_us"
            if "protection.outlook.com" in txt:
                return "microsoft_us"

    if tara == "RO":
        return "local_ro"
    if tara:
        return f"foreign_{tara}"

    if domeniu.endswith(".ro") and mx_records:
        return "local_ro"

    return "unknown"


with open(INPUT_FILE, encoding="utf-8") as f:
    localitati = json.load(f)

if os.path.exists(OUTPUT_FILE):
    with open(OUTPUT_FILE, encoding="utf-8") as f:
        rezultate = json.load(f)
    procesate = {r["wikidata_id"] for r in rezultate}
    print(f"Reluam: {len(procesate)} deja procesate")
else:
    rezultate = []
    procesate = set()

de_procesat = [l for l in localitati if l["domeniu"] and l["wikidata_id"] not in procesate]
print(f"De procesat: {len(de_procesat)}")

for i, loc in enumerate(de_procesat):
    domeniu = loc["domeniu"]
    print(f"[{i+1}/{len(de_procesat)}] {loc['nume']} ({domeniu})")

    mx  = get_mx(domeniu)
    time.sleep(0.2)
    txt = get_txt(domeniu)
    time.sleep(0.1)

    spf    = next((t for t in txt if t.startswith("v=spf1")), None)
    mx_ip  = None
    tara   = None
    org    = ""

    if mx:
        mx_ip = get_ip(mx[0]["host"])
        time.sleep(0.1)
        if mx_ip:
            tara, org = get_ip_info(mx_ip)
            time.sleep(0.2)

    rezultate.append({
        **loc,
        "mx_records": mx,
        "spf":        spf,
        "mx_ip":      mx_ip,
        "tara":       tara,
        "org":        org,
        "provider":   classify(mx, txt, tara, domeniu),
    })

    if (i + 1) % SAVE_EVERY == 0:
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            json.dump(rezultate, f, ensure_ascii=False, indent=2)
        print(f"  Salvat progres: {len(rezultate)} total")

    time.sleep(0.3)

with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
    json.dump(rezultate, f, ensure_ascii=False, indent=2)

print(f"\nGata. {len(rezultate)} localitati in {OUTPUT_FILE}")
