#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import struct
import csv
from collections import Counter


def read_domains(path: str) -> list[str]:
    domains: list[str] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                domains.append(line)
    if not domains:
        raise ValueError("domains.txt is empty.")
    return domains


def iter_pcap_packets(pcap_path: str):
    with open(pcap_path, "rb") as f:
        gh = f.read(24)
        if len(gh) != 24:
            raise ValueError("Incomplete PCAP global header.")
        magic, = struct.unpack("<I", gh[:4])
        if magic != 0xA1B2C3D4:
            raise ValueError("Unsupported PCAP format (expected classic little-endian PCAP).")

        pkt_no = 0
        while True:
            ph = f.read(16)
            if not ph:
                break
            if len(ph) != 16:
                raise ValueError("Incomplete PCAP packet header.")
            ts_sec, ts_usec, incl_len, _orig_len = struct.unpack("<IIII", ph)
            data = f.read(incl_len)
            if len(data) != incl_len:
                raise ValueError("Incomplete PCAP packet data.")
            pkt_no += 1
            ts = ts_sec + ts_usec / 1_000_000
            yield pkt_no, ts, incl_len, data


def detect_ipv4_offset(pkt: bytes) -> int | None:
    for off in (20, 16, 14):
        if off < len(pkt) and (pkt[off] >> 4) == 4:
            return off
    return None


def parse_ipv4(pkt: bytes, off: int):
    if off + 20 > len(pkt):
        return None
    ver_ihl = pkt[off]
    ver = ver_ihl >> 4
    ihl = (ver_ihl & 0x0F) * 4
    if ver != 4 or ihl < 20 or off + ihl > len(pkt):
        return None
    proto = pkt[off + 9]
    src_ip = ".".join(map(str, pkt[off + 12:off + 16]))
    dst_ip = ".".join(map(str, pkt[off + 16:off + 20]))
    return {"ihl": ihl, "proto": proto, "src": src_ip, "dst": dst_ip}


def parse_udp(pkt: bytes, off: int):
    if off + 8 > len(pkt):
        return None
    sport, dport, udp_len, _csum = struct.unpack("!HHHH", pkt[off:off + 8])
    return {"sport": sport, "dport": dport, "udp_len": udp_len}


def build_size_to_domain_map(pcap_path: str, domains_path: str, server_port: int) -> dict[int, str]:
    domains = read_domains(domains_path)

    resp_sizes: list[int] = []
    for _no, _ts, _incl, raw in iter_pcap_packets(pcap_path):
        ip_off = detect_ipv4_offset(raw)
        if ip_off is None:
            continue
        ip = parse_ipv4(raw, ip_off)
        if not ip or ip["proto"] != 17:
            continue
        udp = parse_udp(raw, ip_off + ip["ihl"])
        if not udp or udp["sport"] != server_port:
            continue
        payload_len = max(0, udp["udp_len"] - 8)
        resp_sizes.append(payload_len)

    if not resp_sizes:
        raise ValueError("No responses found for udp.srcport == server_port. Check server_port.")

    distinct_sizes = sorted(set(resp_sizes))
    domains_sorted = sorted(domains, key=len)

    size_to_domain: dict[int, str] = {}
    for i in range(min(len(distinct_sizes), len(domains_sorted))):
        size_to_domain[distinct_sizes[i]] = domains_sorted[i]

    return size_to_domain


def main():
    ap = argparse.ArgumentParser(description="Ex3 DoH Whispers - transactions-only output with tx_no")
    ap.add_argument("-p", "--pcap", default="doh_whispers_capture.pcap", help="Path to PCAP file")
    ap.add_argument("-d", "--domains", default="domains.txt", help="Path to domains.txt")
    ap.add_argument("--server-port", type=int, default=4433, help="Server UDP port (filter udp.srcport==PORT)")
    ap.add_argument("-o", "--out", default="ex3_map_transactions.txt", help="Output file path (.txt/.tsv/.csv)")
    ap.add_argument("--csv", action="store_true", help="Write CSV instead of tab-separated text")
    ap.add_argument("--include-mapping-header", action="store_true",
                    help="If not CSV, prepend mapping lines starting with '# '")
    args = ap.parse_args()

    size_to_domain = build_size_to_domain_map(args.pcap, args.domains, args.server_port)

    out_lower = args.out.lower()
    write_csv = args.csv or out_lower.endswith(".csv")
    delim = "," if write_csv else "\t"

    resp_sizes = []
    for _no, _ts, _incl, raw in iter_pcap_packets(args.pcap):
        ip_off = detect_ipv4_offset(raw)
        if ip_off is None:
            continue
        ip = parse_ipv4(raw, ip_off)
        if not ip or ip["proto"] != 17:
            continue
        udp = parse_udp(raw, ip_off + ip["ihl"])
        if udp and udp["sport"] == args.server_port:
            resp_sizes.append(max(0, udp["udp_len"] - 8))
    counts = Counter(resp_sizes)

    headers = ["tx_no", "no", "time", "source", "destination", "protocol", "length", "info", "domain"]

    with open(args.out, "w", encoding="utf-8", newline="") as f:
        if args.include_mapping_header and not write_csv:
            f.write("# size_to_domain\n")
            for s in sorted(size_to_domain):
                f.write(f"# {s} -> {size_to_domain[s]} (count={counts.get(s, 0)})\n")
            f.write("\n")

        if write_csv:
            w = csv.writer(f)
            w.writerow(headers)
        else:
            f.write(delim.join(headers) + "\n")

        tx_no = 0
        for pkt_no, ts, incl_len, raw in iter_pcap_packets(args.pcap):
            ip_off = detect_ipv4_offset(raw)
            if ip_off is None:
                continue

            ip = parse_ipv4(raw, ip_off)
            if not ip or ip["proto"] != 17:
                continue

            udp = parse_udp(raw, ip_off + ip["ihl"])
            if not udp:
                continue

            if udp["sport"] != args.server_port:
                continue

            payload_len = max(0, udp["udp_len"] - 8)
            info = f"{udp['sport']} → {udp['dport']} Len={payload_len}"
            domain = size_to_domain.get(payload_len, "UNKNOWN")

            tx_no += 1
            row = [
                tx_no,
                pkt_no,
                f"{ts:.6f}",
                ip["src"],
                ip["dst"],
                "UDP",
                incl_len,
                info,
                domain
            ]

            if write_csv:
                w.writerow(row)
            else:
                f.write(delim.join(map(str, row)) + "\n")

    print("[OK] wrote:", args.out)
    print("Size -> Domain mapping:")
    for k in sorted(size_to_domain):
        print(f"  {k} -> {size_to_domain[k]}")


if __name__ == "__main__":
    main()
