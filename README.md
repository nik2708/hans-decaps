# hans-decaps

**Decapsulate IPv4/IPv6 traffic tunnelled with [hans](https://github.com/friedrich/hans) over ICMP.**

![python](https://img.shields.io/badge/python-3.6%2B-3776AB?logo=python&logoColor=white)
![deps](https://img.shields.io/badge/dependencies-none-22c55e)
![license](https://img.shields.io/badge/license-MIT-blue)

hans is a "ping tunnel": it hides IP packets inside ICMP echo payloads, which makes it handy
for getting traffic out through firewalls that only allow pings, and equally handy to look
for during incident response and CTFs.

This tool walks an ICMP tunnel capture, extracts the tunnelled IPv4/IPv6 packets and writes
them to a fresh PCAP so you can open the inner traffic in Wireshark, tcpdump, Zeek or Scapy
like any other captured traffic.

---

## How hans looks on the wire

Every ICMP payload in a hans tunnel starts with a 5-byte header:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| "hanc" / "hans" (4 bytes)     |  magic = direction
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     type      |  ...          |  type 7 = TYPE_DATA, then the inner IP packet
+-+-+-+-+-+-+-+-+
```

* `hanc` — client → server
* `hans` — server → client

Types, from `hans/src/worker.h`:

| # | Type | | # | Type |
|---|------|---|----|------|
| 1 | RESET_CONNECTION | | 6 | CHALLENGE_ERROR |
| 2 | CONNECTION_REQUEST | | **7** | **DATA** |
| 3 | CHALLENGE | | 8 | POLL |
| 4 | CHALLENGE_RESPONSE | | 9 | SERVER_FULL |
| 5 | CONNECTION_ACCEPT | | | |

Only `TYPE_DATA` (7) carries an inner IP packet; everything else is tunnel housekeeping.

---

## Usage

1. Put the capture path in `INPUT_FILE` (and optionally `OUTPUT_FILE`) at the top of
   `hans_decrypt.py`:

   ```python
   INPUT_FILE = "your_dump.pcap"
   OUTPUT_FILE = "hans_decapsulated.pcap"
   ```

2. Run it:

   ```bash
   python hans_decrypt.py
   ```

   ```text
   [+] Analysis completed
   [+] Hans packets found:     27305
   [+] TYPE_DATA packets:      13575
   [+] IPv4 packets extracted: 13543
   [+] IPv6 packets extracted: 32
   [!] Invalid DATA packets:   0
   [+] Output saved to:        hans_decapsulated.pcap
   ```

3. Open `hans_decapsulated.pcap` in Wireshark. It is written as **DLT_RAW** (link type 101),
   so every frame is a bare IPv4/IPv6 packet — the tunnel is gone and the inner traffic is
   visible directly.

Or import it as a module:

```python
import hans_decrypt

stats = hans_decrypt.decapsulate("session.pcap", "session.decaps.pcap")
print(stats)
```

---

## What it handles

| Input | Supported |
|---|---|
| Classic pcap, little endian | ✅ |
| Classic pcap, big endian | ✅ |
| pcapng | ❌ (classic pcap only) |
| Ethernet + IPv4 + ICMP | ✅ |
| VLAN / non-Ethernet link types | ❌ |
| Outer IPv6 transport | ❌ |
| Inner IPv4 payload | ✅ |
| Inner IPv6 payload | ✅ |
| Fragmented ICMP | first fragment only |

Every `TYPE_DATA` payload is written, including fragments. This means that when the same
tunnel packet was captured twice — once as ICMP echo request and once as the matching echo
reply — both copies land in the output. That keeps the export faithful to the capture; if
you want a de-duplicated view, filter it in Wireshark or analyse on the tun interface.

---

## Reference output on a real session

A two-way SSH session tunnelled through ICMP (27 305 tunnel frames):

```
Hans packets found:     27305   (all TYPE_DATA + POLL + handshake)
TYPE_DATA packets:      13575
IPv4 packets extracted: 13543
IPv6 packets extracted: 32
```

Inside the extracted capture: TCP sessions from `10.1.2.100` to `10.1.2.1:22` and ICMPv6
neighbour solicitation from `fe80::8342:31d9:f570:5f45` to `ff02::2`.

---

## Limitations

* Classic pcap only — pcapng, VLAN tags, Linux SLL and raw-IP inputs are rejected.
* Outer header must be Ethernet + IPv4 + ICMP; IPv6 as the transport is not handled.
* IP fragments on the outer layer are not reassembled.
* Paths are edited in the source; there is no command-line interface.

## Legal

For incident responders, CTF players and network administrators investigating traffic. Only
analyse captures you are authorised to handle.

MIT licensed. hans itself is GPLv3, copyright Friedrich Schöller.
