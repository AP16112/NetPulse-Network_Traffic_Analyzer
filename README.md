# NetPulse — Real-Time Network Traffic Analyzer

A Python, Scapy, and Streamlit project for exploring network protocols through actual packet headers. Start with a synthetic demo, inspect saved PCAP/PCAPNG captures, or monitor an authorized local interface.

## Run on Windows

From this directory in PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m streamlit run app.py
```

Open http://localhost:8501. The preloaded demo works without Npcap or administrator permissions. On subsequent runs, use ` .\run.ps1` or the final command above. Python 3.11 or newer is recommended.

For live capture, install [Npcap](https://npcap.com/#download), as described by the [Scapy installation guide](https://scapy.readthedocs.io/en/latest/installation.html). Restart the app, select **Live capture**, choose your Wi-Fi/Ethernet interface, then press **Start**. Depending on Npcap's installation settings, administrator privileges may be required. Use only interfaces and traffic you have permission to monitor. No driver is installed automatically.

## Features

- Real-time local capture with start/stop controls and optional BPF filters, such as `tcp`, `udp port 53`, or `icmp`.
- IPv4, IPv6, Ethernet, 802.1Q VLAN, ARP, TCP, UDP, ICMP/ICMPv6, DNS, and DHCP decoding.
- Source/destination addresses, transport ports, packet sizes, TTL/hop limit, TCP flags, ICMPv4 type, and DNS names/direction.
- Traffic rate chart, protocol distribution, top sources, DNS activity, searchable packet table, and individual header inspection.
- Configurable traffic spike alerts and CSV/JSONL metadata exports.
- OSI guide explaining what is and is not observable in captured packets.
- PCAP/PCAPNG import and repeatable synthetic demo with known spikes.

## Demonstration walkthrough

1. Open the demo and examine the two seeded spikes under **Spike alerts**.
2. Compare the DNS slice with UDP/TCP in **Protocol mix**. DNS is counted once as an application protocol; transport is preserved in its decoded path.
3. In **Packet explorer**, filter DNS, search `example.com`, and inspect a packet's layer path.
4. Explain TCP flags and compare port-bearing TCP/UDP packets with portless ICMP packets.
5. Press **Start** to stream demo packets; a synthetic burst occurs every 30 ticks. Change detection settings to see how thresholds affect alerts.
6. Import a capture or use your local interface, then export the filtered metadata.

To generate a reproducible PCAP for an offline demonstration, run:

```powershell
.\.venv\Scripts\python.exe -m netpulse.sample
```

Import the resulting `sample.pcap` through **PCAP file** mode. This generator constructs packets locally and never transmits them.

## Detection design

The supplied HPE university hiring description emphasizes TCP/UDP, IP addressing, VLANs, the OSI model, ARP, ICMP, DNS, and DHCP. These are represented in the packet inspector and field guide. The project also demonstrates troubleshooting, lab simulation, and automated testing. It does not implement routing protocols such as BGP/OSPF or replace the role's separate certification requirements.

Packets are grouped into one-second UTC buckets, including zero-traffic seconds. A bucket is flagged when its count exceeds both the configured minimum (default 40 packets/s) and a multiplier (default 3×) of the preceding 20-bucket mean. At least five preceding seconds are required. The newest bucket is excluded because it may be incomplete. The chart and detection are bounded to the latest hour of retained traffic.

This is a basic volume-anomaly demonstration. It does not establish malicious intent, reconstruct connections, decrypt TLS, or provide production intrusion detection. A legitimate download can cause a spike, while low-volume attacks may produce no alert. The first five seconds are a warm-up period.

## Architecture and limits

`app.py` renders the dashboard using a [Streamlit fragment](https://docs.streamlit.io/develop/api-reference/execution-flow/st.fragment) refreshed every second. `netpulse/capture.py` owns a session-local worker and a lock-protected bounded deque. It holds a capture socket open across polling intervals and stops after 60 seconds without a dashboard heartbeat. Stop capture before closing the tab for immediate cleanup. Background-tab timer throttling may also stop capture.

`netpulse/packets.py` extracts header metadata; raw payloads are not retained. `netpulse/analysis.py` aggregates traffic and detects spikes. Each browser session has independent storage. At most 15,000 packet records are retained; older records are evicted and reported. PCAP imports parse only the first 15,000 packets and accept files up to 25 MB. Exports contain retained, filtered metadata, not raw packets; metadata may include private addresses and DNS names. No automatic disk log is written: use the export buttons to save a log.

Capture is limited to what the selected interface and OS expose. It does not see every device on a switched network. High-rate capture can lose packets in the OS/driver; eviction counts are not driver drop measurements. OSI layers 1, 5, and 6 cannot generally be independently inferred from these headers. This app defaults to a localhost-only server.

## Tests

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe -m pytest -q
```

Tests cover header decoding, IPv6 DNS, ICMP and ARP, bounded retention, time bucketing, spike thresholds, PCAP import, malformed captures, and the seeded demo. Live capture requires a working OS capture driver and is tested separately from offline behavior.
