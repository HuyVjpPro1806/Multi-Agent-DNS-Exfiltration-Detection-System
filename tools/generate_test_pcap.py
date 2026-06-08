"""
tools/generate_test_pcap.py
Stage 1 — helper script

Generates data/input/demo.pcap containing a mix of benign and
malicious DNS query packets for pipeline testing and demo.

Run:
    python tools/generate_test_pcap.py
"""

from pathlib import Path
from scapy.all import IP, UDP, DNS, DNSQR, wrpcap

OUTPUT_PATH = Path("data/input/demo.pcap")

# ── Domain list ───────────────────────────────────────────────────────────────
# (domain, src_ip, expected_label)
DOMAINS = [
    # Benign
    ("google.com",          "192.168.1.10", "benign"),
    ("github.com",          "192.168.1.11", "benign"),
    ("stackoverflow.com",   "192.168.1.12", "benign"),
    ("cloudflare.com",      "192.168.1.10", "benign"),
    ("youtube.com",         "192.168.1.13", "benign"),
    ("wikipedia.org",       "192.168.1.14", "benign"),
    ("reddit.com",          "192.168.1.11", "benign"),
    ("amazon.com",          "192.168.1.15", "benign"),

    # Malicious — high entropy subdomains (simulating data exfiltration)
    ("a3f9bc12xk29.evil.com",           "10.0.0.5",  "malicious"),
    ("d4e8f2a1b7c3.tunnel.net",         "10.0.0.5",  "malicious"),
    ("xk29ab88zq11.exfil.io",           "10.0.0.6",  "malicious"),
    ("9f3d2c1e8b7a.bad-domain.org",     "10.0.0.7",  "malicious"),
    ("q7w2e5r8t1y4.covert.net",         "10.0.0.5",  "malicious"),

    # Malicious — DGA-style (random-looking, no real subdomain)
    ("xkq9zbf3mw.com",      "10.0.0.8",  "malicious"),
    ("p4j7rvn2ks.net",      "10.0.0.8",  "malicious"),
    ("b8tz1qmx5w.org",      "10.0.0.9",  "malicious"),

    # Repeat queries (same domain, same src — tests count field)
    ("a3f9bc12xk29.evil.com", "10.0.0.5", "malicious"),
    ("a3f9bc12xk29.evil.com", "10.0.0.5", "malicious"),
    ("google.com",            "192.168.1.10", "benign"),
]


def generate(output_path: Path = OUTPUT_PATH) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    packets = []

    for domain, src_ip in [(d, s) for d, s, _ in DOMAINS]:
        pkt = (
            IP(src=src_ip, dst="8.8.8.8")
            / UDP(sport=12345, dport=53)
            / DNS(rd=1, qd=DNSQR(qname=domain, qtype="A"))
        )
        packets.append(pkt)

    wrpcap(str(output_path), packets)
    print(f"Generated {len(packets)} packets → {output_path}")
    print("Breakdown:")
    benign    = sum(1 for _, _, l in DOMAINS if l == "benign")
    malicious = sum(1 for _, _, l in DOMAINS if l == "malicious")
    print(f"  Benign:    {benign}")
    print(f"  Malicious: {malicious}")


if __name__ == "__main__":
    generate()