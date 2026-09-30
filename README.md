# Computer Networks Security Project

A hands-on networking and security project that implements several real-world attack and defense scenarios on a self-hosted infrastructure: a DNS ad blocker with DNS over HTTPS, an interactive map of email providers for Romanian localities (MXMap), ARP spoofing, TCP session hijacking, and DNS tunneling.

## Context

This is a university project developed for the Computer Networks course at the Faculty of Mathematics and Computer Science, University of Bucharest. The work is organized as a set of independent components, each one corresponding to a specific course requirement.

## Components

1. **Infrastructure setup (VPS, domain, TLS)** - Self-hosted setup on a DigitalOcean VPS with a custom domain and a Let's Encrypt TLS certificate, orchestrated with Docker Compose and served through nginx as a reverse proxy.
2. **DNS Ad Blocker (DNS over HTTPS)** - Custom DNS resolver that blocks advertising and tracking domains using a curated blacklist, implements caching and recursive resolution, and exposes both a UDP 53 service and a DNS over HTTPS endpoint.
3. **MXMap** - Interactive Leaflet map of Romania that colors each locality by the email provider of its city hall (local, Google, Microsoft, and other foreign providers). Providers are detected by querying MX and TXT (SPF) records with Scapy; locality data is extracted from Wikidata via SPARQL.
4. **ARP Spoofing** - ARP cache poisoning attack built with Scapy, run inside a multi-container Docker topology (client, router, middle, server) that simulates a man-in-the-middle position on a local network.
5. **TCP Hijacking** - Session hijacking attack that intercepts TCP traffic with NetfilterQueue, injects or rewrites payloads, and can modify arbitrary HTML content served over HTTP.
6. **DNS Tunnel** - Client/server pair that transfers arbitrary files over malformed DNS packets, with a stop-and-wait reliability mechanism, retransmissions, and MD5 checksum verification.

## Technology stack

- Python 3, Scapy, NetfilterQueue
- Docker and Docker Compose
- nginx (reverse proxy and TLS termination)
- Leaflet.js
- Wikidata SPARQL API

## Repository structure

```
.
├── docker-compose.yml           # client / router / middle / server topology
├── docker-compose.dns.yml       # DNS ad blocker + nginx (DoH) stack
├── docker/
│   └── Dockerfile
├── nginx/
│   ├── certs/                   # TLS certificates
│   └── nginx.conf
└── src/
    ├── dns_server.py            # DNS resolver, ad blocker, DoH endpoint
    ├── dns_stats.py             # statistics over blocked domains
    ├── blacklist.txt            # curated ad/tracking domain list
    ├── mxmap_wikidata.py        # Wikidata (SPARQL) extraction
    ├── mxmap_dns_scan.py        # MX/TXT scanning with Scapy
    ├── mxmap.html               # interactive Leaflet map
    ├── mxmap_data.json          # processed locality/provider data
    ├── arp_spoof.py             # ARP cache poisoning
    ├── tcp_client.py            # TCP client
    ├── tcp_server.py            # TCP server
    ├── tcp_hijack.py            # TCP payload injection
    ├── alter_packages.sh        # network impairment rules (netem)
    ├── dns_tunnel_server.py     # DNS tunnel server
    ├── dns_tunnel_client.py     # DNS tunnel client
    └── client.sh, server.sh, middle.sh, router.sh
```

## Status

All core requirements are implemented. The optional bonus requirement (HTTP Request Smuggling or DNS SOCKS5 proxy) was not implemented.
