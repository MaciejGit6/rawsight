#!/usr/bin/env python3
"""Generates the edge-case captures in tests/data/.

The outputs are committed, so this only needs re-running when adding a case:
    python3 tests/gen_pcaps.py
"""
import os
import struct

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")

SRC_MAC = b"\xbb" * 6
DST_MAC = b"\xaa" * 6
SRC_IP = bytes([10, 0, 0, 1])
DST_IP = bytes([10, 0, 0, 2])


def ipv4(proto, payload, frag=0):
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 1, frag,
                      64, proto, 0, SRC_IP, DST_IP)
    return hdr + payload


def udp(sport, dport, payload):
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def eth(payload):
    return DST_MAC + SRC_MAC + b"\x08\x00" + payload


def write(name, frames, endian="<", linktype=1):
    with open(os.path.join(OUT, name), "wb") as f:
        f.write(struct.pack(endian + "IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for fr in frames:
            f.write(struct.pack(endian + "IIII", 0, 0, len(fr), len(fr)) + fr)


COAP_GET = bytes([0x40, 0x01, 0x12, 0x34])  # CON GET MID=0x1234, no token
coap_frame = eth(ipv4(17, udp(40000, 5683, COAP_GET)))

# two 120-byte Uri-Path segments + Uri-Query: used to overflow the info buffer
seg = b"A" * 120
opts = (bytes([0xBD, 120 - 13]) + seg + bytes([0x0D, 120 - 13]) + seg
        + bytes([0x4D, 20 - 13]) + b"Q" * 20)
write("coap_long_uri.pcap", [eth(ipv4(17, udp(40000, 5683, COAP_GET + opts)))])

# ethernet padding after the IP datagram that looks like a Uri-Path option
pad = bytes([0xB3]) + b"xyz"
write("coap_padded.pcap", [coap_frame + pad + b"\x00" * (60 - len(coap_frame) - len(pad))])

# non-first IPv4 fragment (offset 16 * 8 bytes) - no UDP header inside
write("ipv4_fragment.pcap", [eth(ipv4(17, b"\xde\xad" * 10, frag=0x0010))])

# same CoAP GET, file written big-endian
write("coap_bigendian.pcap", [coap_frame], endian=">")

# linux cooked capture (link type 113) - not supported
write("linktype_sll.pcap", [coap_frame], linktype=113)
