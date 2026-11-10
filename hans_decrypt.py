#!/usr/bin/env python3
"""Decapsulate IPv4/IPv6 traffic tunnelled with hans over ICMP.

Hans (https://github.com/friedrich/hans) hides layer-3 packets inside ICMP
echo payloads.  Each payload starts with a 5-byte tunnel header:

        +--------+--------+--------+--------+--------+
        | magic (4 bytes) | type (1 byte)          |
        +--------+--------+--------+--------+--------+
          "hanc" = client -> server       type 7 = TYPE_DATA (real payload)
          "hans" = server -> client       (see worker.h of hans for all types)

Only TYPE_DATA frames carry the tunnelled IP packet (the bytes after the
header).  This script walks a capture, extracts those packets and writes them
to a new capture as raw IP (DLT_RAW), so Wireshark / tcpdump can read the
inner traffic as ordinary layer-3 packets.

Pure Python 3 standard library - no dependencies.
"""

import struct
import sys

INPUT_FILE = "your_dump.pcap"
OUTPUT_FILE = "hans_decapsulated.pcap"

HANS_MAGICS = (b"hans", b"hanc")
TYPE_DATA = 7


def ip_version(data):
    """Return the IP version of a packet (4 or 6) or None."""
    if not data:
        return None

    version = data[0] >> 4

    if version in (4, 6):
        return version

    return None


def read_global_header(f):
    """Read the 24-byte pcap header and return the byte order."""
    global_header = f.read(24)

    if len(global_header) != 24:
        raise ValueError("Invalid PCAP file")

    magic = global_header[:4]

    if magic == b"\xd4\xc3\xb2\xa1":
        return "<"
    if magic == b"\xa1\xb2\xc3\xd4":
        return ">"

    raise ValueError("Unsupported PCAP magic: %s" % magic.hex())


def iter_frames(f, endian):
    """Yield (ts_sec, ts_usec, frame) for every packet in the capture."""
    packet_header_fmt = struct.Struct(endian + "IIII")

    while True:
        packet_header = f.read(16)

        if len(packet_header) < 16:
            return

        ts_sec, ts_usec, incl_len, _orig_len = packet_header_fmt.unpack(packet_header)

        frame = f.read(incl_len)

        if len(frame) != incl_len:
            return

        yield ts_sec, ts_usec, frame


def extract_hans_payload(frame):
    """Return the ICMP data field if the frame is a hans tunnel packet."""
    # Minimum: Ethernet (14) + IPv4 (20) + ICMP header (8)
    if len(frame) < 14 + 20 + 8:
        return None

    ethertype = struct.unpack("!H", frame[12:14])[0]

    if ethertype != 0x0800:  # IPv4 only
        return None

    ip_offset = 14

    if frame[ip_offset] >> 4 != 4:
        return None

    ip_header_length = (frame[ip_offset] & 0x0F) * 4

    if ip_header_length < 20:
        return None

    if len(frame) < ip_offset + ip_header_length + 8:
        return None

    protocol = frame[ip_offset + 9]

    if protocol != 1:  # ICMP
        return None

    icmp_offset = ip_offset + ip_header_length

    # Skip the 8-byte ICMP header (type, code, checksum, id, seq).
    return frame[icmp_offset + 8:]


def decapsulate(input_file, output_file):
    """Extract every hans TYPE_DATA payload and write a DLT_RAW capture."""
    stats = {
        "hans_packets": 0,
        "data_packets": 0,
        "ipv4_packets": 0,
        "ipv6_packets": 0,
        "invalid_packets": 0,
    }
    extracted_packets = []

    with open(input_file, "rb") as f:
        endian = read_global_header(f)

        for ts_sec, ts_usec, frame in iter_frames(f, endian):
            payload = extract_hans_payload(frame)

            if payload is None or len(payload) < 5:
                continue

            magic = payload[:4]

            if magic not in HANS_MAGICS:
                continue

            stats["hans_packets"] += 1

            packet_type = payload[4]

            if packet_type != TYPE_DATA:
                continue

            stats["data_packets"] += 1

            # Strip the hans header: 4 bytes magic + 1 byte type.
            inner_packet = payload[5:]
            version = ip_version(inner_packet)

            if version == 4:
                stats["ipv4_packets"] += 1
            elif version == 6:
                stats["ipv6_packets"] += 1
            else:
                stats["invalid_packets"] += 1
                continue

            extracted_packets.append((ts_sec, ts_usec, inner_packet))

    write_raw_capture(output_file, extracted_packets)
    return stats


def write_raw_capture(output_file, packets):
    """Write packets as link type 101 (DLT_RAW) with a classic pcap header."""
    new_global_header = struct.pack(
        "<IHHIIII",
        0xA1B2C3D4,  # magic
        2,           # major version
        4,           # minor version
        0,           # timezone
        0,           # sigfigs
        65535,       # snaplen
        101,         # DLT_RAW
    )

    record_fmt = struct.Struct("<IIII")

    with open(output_file, "wb") as out:
        out.write(new_global_header)

        for ts_sec, ts_usec, packet in packets:
            length = len(packet)
            out.write(record_fmt.pack(ts_sec, ts_usec, length, length))
            out.write(packet)


def main():
    try:
        stats = decapsulate(INPUT_FILE, OUTPUT_FILE)
    except (OSError, ValueError) as exc:
        sys.stderr.write("error: %s\n" % exc)
        return 2

    print("[+] Analysis completed")
    print("[+] Hans packets found:     %d" % stats["hans_packets"])
    print("[+] TYPE_DATA packets:      %d" % stats["data_packets"])
    print("[+] IPv4 packets extracted: %d" % stats["ipv4_packets"])
    print("[+] IPv6 packets extracted: %d" % stats["ipv6_packets"])
    print("[!] Invalid DATA packets:   %d" % stats["invalid_packets"])
    print("[+] Output saved to:        %s" % OUTPUT_FILE)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
