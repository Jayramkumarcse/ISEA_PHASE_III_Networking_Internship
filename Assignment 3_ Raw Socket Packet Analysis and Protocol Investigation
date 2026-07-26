# 03 — Raw Socket Packet Analysis and Protocol Investigation

## Objective
Use a Linux raw socket in C to capture and decode live IP traffic for a
protocol assigned by roll number, cross-verify results against Wireshark,
and analyse IP header field behaviour.

## Protocol Assignment (last digit of roll number)
| Last digit | Protocol |
|---|---|
| 0-3 | ICMP |
| 4-6 | UDP |
| 7-9 | TCP |

`raw_capture.c` computes this automatically from `--roll` — no manual editing.

## How It Works
Opens an `AF_PACKET`/`SOCK_RAW` socket bound to `ETH_P_IP`, which delivers
full Ethernet frames for **all** IP traffic on the chosen interface. The
program then parses the Ethernet header, the `struct iphdr`, and — only
for frames whose `ip->protocol` matches the assigned protocol number
(1=ICMP, 17=UDP, 6=TCP) — the relevant Layer‑4 header (`icmphdr`, `udphdr`,
or `tcphdr`), printing the required key=value block per packet.

## Build
```bash
gcc raw_capture.c -o raw_capture
```
Compiled clean with `-Wall -Wextra`, zero warnings.

## Run (requires root — raw sockets need CAP_NET_RAW)
```bash
sudo ./raw_capture --roll <YOUR_ROLL_NO> --iface eth0 --count 20 --extra ttl
```
| Flag | Meaning |
|---|---|
| `--roll` | Your roll number — determines the assigned protocol |
| `--iface` | Interface to bind to (use the Mininet host's interface, e.g. `h1-eth0`) |
| `--count` | Minimum matching packets to capture before exiting (default 20) |
| `--extra` | One of `version`, `ihl`, `id`, `tos`, `frag` — prints the Task 5 bonus field |

## Generating Traffic (in a second terminal, matching your assigned protocol)
| Protocol | Example command |
|---|---|
| ICMP | `ping 8.8.8.8` |
| TCP | `nc -v <ip> <port>` / `ssh <host>` |
| UDP | `nc -u <ip> <port>` / `iperf -u -c <server-ip>` |

## Wireshark Verification (third terminal / GUI)
```bash
sudo tshark -i <iface> -w capture.pcapng
```
Filter by protocol: `icmp`, `tcp`, `udp`, or `ip.proto == 1/6/17`.
Cross-check 5 frames against the program's output (frame no., IPs,
protocol, TTL, size) in the report's comparison table.

## Files
```
03-raw-socket-analysis/
├── raw_capture.c
├── program_output.txt        (generated: redirect stdout of a real run)
├── capture.pcapng             (from Wireshark/tshark)
├── screenshots/
│   ├── traffic_generation.png
│   ├── program_output.png
│   ├── wireshark_packets.png
│   └── comparison_packets.png
└── report.pdf
```

## Verified
Compiled with `gcc -Wall -Wextra` — zero warnings/errors. Confirmed the
program correctly refuses to run without root (`CAP_NET_RAW` required),
matching expected raw-socket behaviour. **Actual packet capture must be
run by you** inside your Mininet/lab environment with `sudo` and real
generated traffic — this cannot be produced in a sandboxed build
environment and must reflect your own experiment per the assignment's
integrity requirements.

## Reflection Questions (report.pdf)
Why are root privileges required for raw sockets? · How do raw sockets
differ from TCP/UDP sockets? · One advantage and one limitation of raw
sockets · One networking/cybersecurity application of raw sockets.
