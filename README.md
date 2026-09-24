# NetGuard SOC — Enterprise Network Intrusion Detection System & Live Telemetry

[![Python](https://img.shields.io/badge/Python-3.11%20%7C%203.12-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Framework](https://img.shields.io/badge/Flask--SocketIO-Real--Time-orange.svg)](https://flask-socketio.readthedocs.io/)
[![Detection](https://img.shields.io/badge/Heuristics-6%20Active%20Engines-red.svg)](#detection-engines)
[![UI](https://img.shields.io/badge/UI-Google%20Stitch%20SOC-cyan.svg)](#soc-workspaces)

**NetGuard SOC** is a modular, high-performance Network Intrusion Detection System (NIDS) and Security Operations Center (SOC) dashboard. It captures live network packets via Scapy/libpcap, decodes Layer 2 through Layer 4 headers, evaluates packet streams against six stateful heuristic detection engines, and streams live telemetry, dynamic statistical baseline corridors ($\mu + 2\sigma$), and security incidents to an interactive browser interface over WebSockets.

---

## Key Features

- **6 Stateful Heuristic Detection Engines**: Real-time detection for port scanning, TCP SYN floods, RST/FIN connection teardowns, UDP volumetric floods, ICMP echo saturation, and covert DNS tunneling.
- **Dynamic Statistical Baseline Corridor ($\mu + 2\sigma$)**: Real-time dual-axis Chart.js telemetry plotting link throughput (KB/s) alongside packet rate (PPS), wrapped in a statistical upper ceiling to differentiate benign bursts from hostile volumetric floods.
- **Self-Explaining Diagnostic Interpreter**: Automated real-time banner translating packet size ratios and PPS into plain-English root-cause diagnoses.
- **3 Dedicated SOC Workspaces**:
  1. **Network & Traffic**: Live KPI telemetry, Threat Index (0–100), dual-axis charts, protocol breakdown (TCP/UDP/ICMP), and Top Talker host rankings.
  2. **Threat Radar & Attack Lab**: RFC-compliant multi-vector attack generator, geographical threat radar, and live intrusion event log.
  3. **Host & Packet Forensics**: Stateful TCP 3-way handshake analyzer, host inventory tracker, interactive OSI layer packet dissector, and incident-specific PCAP export.
- **SOAR Active Defense (Kernel Firewall Enforcement)**: Instant generation and deployment of kernel-level firewall drops (`iptables` on Linux, `netsh advfirewall` on Windows, and `pfctl` on macOS).
- **Incident-Specific PCAP Dumps**: On-the-fly ring buffer extraction enabling one-click download of the exact raw Wireshark `.pcap` packets that triggered any alert.
- **Interactive Guided Tour & Rate Multipliers**: Built-in walkthrough tour and dynamic simulation speed throttling (`1x | 3x | 10x`).

---

## Architecture Overview

```
                      +-----------------------------+
                      |   NIC Ingress (libpcap)     |
                      |   or Synthetic Generator    |
                      +--------------+--------------+
                                     |
                                     v
                      +-----------------------------+
                      |     Ring Buffer Queue       |
                      +--------------+--------------+
                                     |
                                     v
                      +-----------------------------+
                      |    PacketParserWorker       |
                      |  (Ether -> IPv4/6 -> L4)    |
                      +--------------+--------------+
                                     |
                                     v
                       PacketEvent [Typed Dataclass]
                                     |
                 +-------------------+-------------------+
                 |                                       |
                 v                                       v
    +-------------------------+             +-------------------------+
    |    Detection Engine     |             |   Metrics Aggregator    |
    |  - PortScanDetector     |             |  - 1 Hz Sliding Window  |
    |  - SynFloodDetector     |             |  - Throughput (KB/s)    |
    |  - RstAbuseDetector     |             |  - Packet Rate (PPS)    |
    |  - UdpFloodDetector     |             |  - Baseline (μ + 2σ)    |
    |  - IcmpFloodDetector    |             |  - Protocol Breakdown   |
    |  - DnsTunnelingDetector |             |  - Host Device Inventory|
    +------------+------------+             +------------+------------+
                 |                                       |
                 v                                       |
    +-------------------------+                          |
    |      Alert Manager      |                          |
    |  - Cooldown & Dedup     |                          |
    |  - PCAP Ring Snapshot   |                          |
    |  - SQLite (netguard.db) |                          |
    +------------+------------+                          |
                 |                                       |
                 +-------------------+-------------------+
                                     |
                                     v
                      +-----------------------------+
                      |   Flask-SocketIO / REST     |
                      |     (127.0.0.1:5050)        |
                      +--------------+--------------+
                                     |
                                     v
                      +-----------------------------+
                      |   Interactive SOC Console   |
                      |   (HTML5, Chart.js, Leaflet)|
                      +-----------------------------+
```

---

## Detection Engines

| # | Detector | File | Heuristic Threshold & Method | Severity |
|---|---|---|---|---|
| **1** | **Vertical / Horizontal Port Scan** | `netguard/detection/port_scan.py` | Tracks unique destination ports probed by each source IP in a sliding 3.0s window. Triggers when unique ports probed $\ge 15$. Classifies vertical (single target) vs horizontal (subnet sweep). | **HIGH / MEDIUM** |
| **2** | **TCP SYN Flood (Half-Open Starvation)** | `netguard/detection/syn_flood.py` | Evaluates incoming SYN packets against outgoing SYN-ACK responses in a 2.0s sliding window. Triggers when SYN count $> 50$ and $\frac{\text{SYN}}{\max(1, \text{SYN-ACK})} > 4.0$. Tracks uncompleted handshakes in state table. | **CRITICAL** |
| **3** | **RST / FIN Session Teardown** | `netguard/detection/rst_abuse.py` | Detects unsolicited TCP RST/FIN packet bursts targeting active TLS/web ports (443, 80, 22, 3389) exceeding 10 packets within 5.0s. | **HIGH** |
| **4** | **UDP Volumetric Flood & Amplification** | `netguard/detection/udp_flood.py` | Monitors connectionless UDP ingress (e.g. UDP 53 / 123). Triggers when packet burst exceeds 40 datagrams within 3.0s. | **HIGH** |
| **5** | **ICMP Echo Flood & Ping Sweep** | `netguard/detection/icmp_flood.py` | Tracks ICMP Type 8 Echo Requests. Triggers when packet volume exceeds 30 datagrams within 3.0s, classifying target saturation vs IP range discovery sweeps. | **MEDIUM** |
| **6** | **DNS Tunneling & Covert Exfiltration** | `netguard/detection/dns_tunneling.py` | Decodes UDP 53 DNS payloads. Analyzes query length and Shannon entropy of labels. Triggers when 15+ anomalous oversized queries (avg length $> 90$ bytes) target external nameservers in a 4.0s window. | **CRITICAL** |

---

## SOC Workspaces

### 1. 📊 Network & Traffic Telemetry
- **Threat Level Meter (0–100)**: Real-time risk index reflecting volumetric anomalies and recent high-severity alerts.
- **Active Security Alerts Counter**: Live intrusion counter with delta notifications.
- **Ingress Telemetry**: Total packet and byte counters with one-click demonstration reset.
- **Dual-Axis Telemetry**: Bandwidth (KB/s) on left Y-axis and Packet Rate (PPS) on right Y-axis, bounded by a dynamic statistical baseline ceiling ($\mu + 2\sigma$).
- **Top Talkers Leaderboard**: Real-time ranked bandwidth consumption by host IP.

### 2. 🛡️ Threat Radar & Attack Lab
- **Interactive Vector Injection**: Launch simulated RFC-compliant attacks directly into the live pipeline:
  - Vertical Port Scans & Subnet Sweeps
  - DNS Tunneling Exfiltration
  - TCP SYN Flood Half-Open Bursts
  - UDP Amplification Floods
  - ICMP Echo Floods
  - RST Session Hijacking
- **Intrusion Event Log**: Live table of detected threats with severity filters and raw heuristic payload inspection.
- **Geographic Threat Radar**: Leaflet world map plotting external attacker coordinates in real time.

### 3. 🔍 Host & Packet Forensics
- **RFC 793 TCP Handshake Analyzer**: Visual state machine displaying SYN &rarr; SYN-ACK &rarr; ESTABLISHED &rarr; FIN connection transitions.
- **Host Device Inventory**: Automated identification of private LAN devices vs external WAN endpoints.
- **Deep Packet Dissector**: Tree view decomposing packets through OSI Layer 2 (MAC/Ethernet), Layer 3 (IPv4/IPv6 TTL, Flags), and Layer 4 (TCP ports, sequences, window sizes).
- **Incident PCAP Export**: Download raw `.pcap` packet dumps for any recorded alert for forensic review in Wireshark.

---

## Installation & Quickstart

### Prerequisites
- Python 3.11 or 3.12
- Git
- Elevated privileges (only required for live physical interface capture)

### Setup
```bash
# Clone the repository
git clone https://github.com/deepanshu214/NetGuard.git
cd NetGuard

# Create and activate a virtual environment
python -m venv .venv

# On Windows:
.venv\Scripts\activate
# On Linux / macOS:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Running NetGuard

#### 1. Simulation / Demo Mode (Recommended — No Root Required)
Runs NetGuard with synthetic network traffic and full attack lab capability:
```bash
python netguard/main.py --mode simulation --port 5050
```
Open **`http://127.0.0.1:5050`** in your browser.

#### 2. Live Interface Sniffing Mode
Captures physical network packets traversing your network interface:
```bash
# Windows (Run PowerShell as Administrator):
python netguard/main.py --mode live -i "Wi-Fi" --port 5050

# Linux / macOS (Requires sudo for raw socket access):
sudo .venv/bin/python netguard/main.py --mode live -i eth0 --port 5050
```

---

## Running the Test Suite

Execute the full automated pytest suite (unit detectors, heuristic mathematics, API endpoints, parser validation):

```bash
python -m pytest tests/ -v
```

All 22 tests verify:
- L3/L4 packet parsing (IPv4, IPv6, TCP flags, UDP, ICMP).
- Sliding-window threshold breaches, sub-threshold silence, and window expiry.
- DNS Tunneling high-entropy detection and normal query tolerance.
- Active defense SOAR rule generation and persistence.
- REST API health, rate simulation, alert management, and PCAP export endpoints.

---

## Directory Structure

```
NetGuard/
├── netguard/
│   ├── capture/            # Async packet sniffer & incident PCAP recorder
│   ├── parsing/            # Layer 2-4 OSI header decoder
│   ├── detection/          # 6 stateful heuristic detectors (Port Scan, SYN, RST, UDP, ICMP, DNS)
│   ├── alerts/             # Cooldown manager, deduplication, SQLite persistence
│   ├── metrics/            # 1 Hz rate aggregator, statistical baseline corridor, device tracker
│   ├── web/                # Flask application, Socket.IO gateway, API routes
│   │   ├── static/         # CSS styles, Chart.js / Leaflet scripts, dashboard.js
│   │   └── templates/      # Responsive SOC dashboard (index.html)
│   ├── config.py           # YAML threshold configuration loader
│   ├── models.py           # Strongly-typed dataclasses (PacketEvent, Alert, MetricSnapshot)
│   ├── simulation.py       # Multi-vector synthetic attack generator
│   └── main.py             # Server lifecycle orchestrator
├── tests/                  # 22 automated unit and integration tests
├── scripts/                # CLI simulation and verification utilities
├── docs/                   # Technical documentation and architecture notes
├── config.yaml             # Detection rules & threshold settings
├── requirements.txt        # Python package dependencies
└── README.md               # Project documentation
```

---

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
