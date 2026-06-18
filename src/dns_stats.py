import os
from collections import Counter

FISIER_LOG = os.path.join(os.path.dirname(__file__), 'domenii_blocate.txt')
FISIER_RAPORT = os.path.join(os.path.dirname(__file__), 'raport_statistici.txt')

CUVINTE_COMPANII = {
    'google': ['google', 'doubleclick', 'googletag', 'googlesyndication', 'googlead'],
    'facebook': ['facebook', 'fbcdn', 'fbsbx', 'meta'],
    'amazon': ['amazon', 'aws', 'cloudfront'],
    'microsoft': ['microsoft', 'bing', 'msn', 'live'],
    'twitter': ['twitter', 'twimg'],
    'yahoo': ['yahoo', 'yimg'],
    'adobe': ['adobe', 'typekit'],
    'oracle': ['oracle', 'bluekai'],
    'criteo': ['criteo'],
    'appnexus': ['appnexus', 'adnxs'],
    'pubmatic': ['pubmatic'],
    'rubicon': ['rubicon', 'rubiconproject'],
    'openx': ['openx'],
    'taboola': ['taboola'],
    'outbrain': ['outbrain'],
}

def gaseste_compania(domeniu):
    mic = domeniu.lower()
    for companie, cuvinte in CUVINTE_COMPANII.items():
        for cuv in cuvinte:
            if cuv in mic:
                return companie
    return None

def analizeaza():
    if not os.path.exists(FISIER_LOG):
        print(f"Nu gasesc fisierul {FISIER_LOG}")
        return

    with open(FISIER_LOG, 'r') as f:
        domenii = [linie.strip() for linie in f if linie.strip()]

    if not domenii:
        print("Niciun domeniu blocat gasit.")
        return

    total = len(domenii)
    unice = len(set(domenii))
    contor = Counter(domenii)
    top_domenii = contor.most_common(50)

    contor_companii = Counter()
    for domeniu in domenii:
        companie = gaseste_compania(domeniu)
        if companie:
            contor_companii[companie] += 1

    cunoscute = sum(contor_companii.values())
    necunoscute = total - cunoscute

    raport = []
    raport.append("=" * 60)
    raport.append("RAPORT STATISTICI DNS ADBLOCKER")
    raport.append("=" * 60)
    raport.append(f"\nTotal cereri blocate: {total}")
    raport.append(f"Domenii unice blocate: {unice}")
    raport.append(f"\nClasificate pe companii: {cunoscute} ({cunoscute*100//total if total else 0}%)")
    raport.append(f"Necunoscute: {necunoscute} ({necunoscute*100//total if total else 0}%)")

    raport.append("\n" + "-" * 40)
    raport.append("BLOCARI PE COMPANII")
    raport.append("-" * 40)
    for companie, nr in contor_companii.most_common():
        procent = nr * 100 // total if total else 0
        raport.append(f"  {companie:20s}: {nr:6d} ({procent}%)")

    raport.append("\n" + "-" * 40)
    raport.append("TOP 30 CELE MAI BLOCATE DOMENII")
    raport.append("-" * 40)
    for domeniu, nr in top_domenii[:30]:
        raport.append(f"  {domeniu:50s}: {nr:6d}")

    raport.append("\n" + "=" * 60)

    text_raport = '\n'.join(raport)
    print(text_raport)

    with open(FISIER_RAPORT, 'w') as f:
        f.write(text_raport)
    print(f"\nRaport salvat in {FISIER_RAPORT}")


if __name__ == '__main__':
    analizeaza()
