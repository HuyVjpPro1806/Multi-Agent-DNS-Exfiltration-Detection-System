"""
tools/pcap_reader.py
Stage 1 — pcap_reader_agent tool

Reads a PCAP/PCAPng file, filters DNS packets (UDP/TCP port 53),
and writes raw_packets.json for dns_extractor_agent.
"""

import json
import logging
from pathlib import Path

from scapy.all import rdpcap, UDP, TCP, IP, raw

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger(__name__)

OUTPUT_PATH = Path("data/output/raw_packets.json")


def read_pcap_file(filepath: str, max_packets: int = 10_000) -> list[dict]:
    """
    Read DNS packets from a PCAP file.

    Args:
        filepath:    Path to .pcap or .pcapng file.
        max_packets: Maximum number of DNS packets to return.

    Returns:
        List of packet dicts. Also writes to data/output/raw_packets.json.
    """
    path = Path(filepath)
    if not path.exists():
        log.error(f"File not found: {filepath}")
        return {"error": "file_not_found", "path": str(filepath)}

    log.info(f"Reading PCAP: {filepath}")
    try:
        packets = rdpcap(str(path))
    except Exception as e:
        log.error(f"Failed to read PCAP: {e}")
        return {"error": "read_failed", "detail": str(e)}

    results = []
    total = len(packets)
    packet_id = 1

    for i, pkt in enumerate(packets):
        if len(results) >= max_packets:
            log.warning(f"Reached max_packets={max_packets}, stopping early.")
            break

        try:
            # Only keep UDP/TCP port 53
            if not pkt.haslayer(IP):
                continue
            if pkt.haslayer(UDP):
                proto = "UDP"
                layer = pkt[UDP]
            elif pkt.haslayer(TCP):
                proto = "TCP"
                layer = pkt[TCP]
            else:
                continue

            if layer.dport != 53 and layer.sport != 53:
                continue

            # Extract DNS payload (everything after transport header)
            payload_bytes = bytes(layer.payload)
            if not payload_bytes:
                continue

            results.append({
                "packet_id":          packet_id,
                "timestamp":          float(pkt.time),
                "src_ip":             pkt[IP].src,
                "dst_ip":             pkt[IP].dst,
                "src_port":           int(layer.sport),
                "dst_port":           int(layer.dport),
                "protocol":           proto,
                "dns_payload_length": len(payload_bytes),
                "raw_payload":        payload_bytes.hex(),
            })
            packet_id += 1

        except Exception as e:
            log.warning(f"Skipping corrupt packet #{i}: {e}")
            continue

    if not results:
        log.warning("No DNS packets found in file.")

    log.info(f"Scanned {total} packets — kept {len(results)} DNS packets.")

    # Write output
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_PATH, "w") as f:
        json.dump(results, f, indent=2)
    log.info(f"Saved → {OUTPUT_PATH}")

    return results


if __name__ == "__main__":
    import sys
    fp = sys.argv[1] if len(sys.argv) > 1 else "data/input/demo.pcap"
    pkts = read_pcap_file(fp)
    if isinstance(pkts, list):
        print(f"Done: {len(pkts)} DNS packets extracted.")