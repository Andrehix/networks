import requests
import json
from urllib.parse import urlparse

SPARQL_ENDPOINT = "https://query.wikidata.org/sparql"
PAGE_SIZE = 1000
OUTPUT = "localitati_wikidata.json"

BASE_QUERY = """
SELECT DISTINCT ?item ?itemLabel ?email ?website ?lat ?lon WHERE {
  ?item p:P31 ?s0 .
  ?s0 (ps:P31/wdt:P279*) wd:Q697379 .
  ?item wdt:P17 wd:Q218 .
  OPTIONAL { ?item wdt:P968 ?email }
  OPTIONAL { ?item wdt:P856 ?website }
  OPTIONAL {
    ?item p:P625 ?s .
    ?s psv:P625 ?c .
    ?c wikibase:geoLatitude  ?lat ;
       wikibase:geoLongitude ?lon .
  }
  SERVICE wikibase:label { bd:serviceParam wikibase:language "ro,en" }
}
"""

HEADERS = {
    "Accept": "application/sparql-results+json",
    "User-Agent": "MXMap-RO/1.0",
}


def domeniu_din_email(email):
    if email and "@" in email:
        return email.split("@")[-1].strip().lower().rstrip(".")
    return None


def domeniu_din_url(url):
    if not url:
        return None
    if not url.startswith("http"):
        url = "http://" + url
    host = urlparse(url).netloc.split(":")[0].lower()
    if host.startswith("www."):
        host = host[4:]
    return host or None


localitati = []
vazute = set()
offset = 0

while True:
    query = BASE_QUERY.strip() + f"\nLIMIT {PAGE_SIZE} OFFSET {offset}"
    print(f"Pagina offset={offset}...")

    resp = requests.get(SPARQL_ENDPOINT, params={"query": query}, headers=HEADERS, timeout=120)
    resp.raise_for_status()
    rows = resp.json()["results"]["bindings"]

    for row in rows:
        wid = row["item"]["value"].split("/")[-1]
        if wid in vazute:
            continue
        vazute.add(wid)

        email   = row.get("email",   {}).get("value")
        website = row.get("website", {}).get("value")
        lat     = row.get("lat",     {}).get("value")
        lon     = row.get("lon",     {}).get("value")

        domeniu = domeniu_din_email(email) or domeniu_din_url(website)

        localitati.append({
            "wikidata_id": wid,
            "nume":    row["itemLabel"]["value"],
            "email":   email,
            "website": website,
            "domeniu": domeniu,
            "lat": float(lat) if lat else None,
            "lon": float(lon) if lon else None,
        })

    print(f"  {len(rows)} randuri primite, total acumulat: {len(localitati)}")

    if len(rows) < PAGE_SIZE:
        break
    offset += PAGE_SIZE

with open(OUTPUT, "w", encoding="utf-8") as f:
    json.dump(localitati, f, ensure_ascii=False, indent=2)

cu_domeniu = sum(1 for l in localitati if l["domeniu"])
print(f"\nTotal: {len(localitati)} | Cu domeniu: {cu_domeniu} | Fara: {len(localitati) - cu_domeniu}")
print(f"Salvat in {OUTPUT}")
