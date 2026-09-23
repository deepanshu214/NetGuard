# NetGuard: Network Intrusion Detection System & Live Monitor

NetGuard is a lightweight Network Intrusion Detection System (NIDS) and real-time web dashboard. It captures live network traffic via Scapy/libpcap, parses Layer 3 and Layer 4 headers, evaluates incoming packets against rule-based detection state machines, and streams real-time traffic statistics and security alerts to a browser interface over WebSockets.

---

## Architecture Overview

```
 [Network Interface (libpcap)]        [Synthetic Traffic Generator]
               \                                    /
                \---> [Bounded queue.Queue] <------/
                               |
                               v
                     [ParserWorker Thread]
                     (Ether -> IP -> TCP/UDP)
                               |
                        PacketEvent
                               |
               +---------------+---------------+
               |                               |
               v                               v
      [Detection Engine]              [Metrics Aggregator]
   - PortScanDetector (Vert/Horiz)      - 1-second interval rates
   - SynFloodDetector (SYN:ACK ratio)   - Throughput (KB/s, pps)
   - RstAbuseDetector                   - Protocol distribution
               |                        - Top talker ranking
               v                               |
        [Alert Manager]                        | 1 Hz
   - Cooldown & dedup                          |
   - SQLite store (netguard.db)                |
               \                               /
                \-----> [Flask-SocketIO] <----/
                               |
                     WebSocket / REST API
                               |
                               v
                     [Browser Dashboard]
```

---

## Detection Rules

1. **Port Scan Detection (`port_scan.py`)**
   - Tracks unique destination ports probed by each source IP within a rolling 3.0-second window.
   - Triggers when unique ports $\ge 15$.
   - Classifies as:
     - **Vertical Scan:** One destination host, multiple ports probed.
     - **Horizontal Scan:** Multiple destination hosts probed on the same port range.

2. **TCP SYN Flood Detection (`syn_flood.py`)**
   - Monitors TCP 3-way handshake state and the ratio of incoming SYN packets to outgoing SYN-ACK responses within a 2.0-second window.
   - Triggers when SYN count $> 50$ and $\frac{\text{SYN}}{\max(1, \text{SYN-ACK})} > 4.0$.
   - Tracks uncompleted half-open connections in a 4-tuple state table expiring after 5 seconds.

3. **RST/FIN Abuse Detection (`rst_abuse.py`)**
   - Monitors unexpected bursts of TCP RST or FIN packets targeting sensitive services (e.g. SSH:22, HTTP:80, HTTPS:443, RDP:3389).
   - Triggers when $\ge 10$ RST/FIN packets from one source target monitored ports within 5.0 seconds.

4. **Alert Management & Throttling (`manager.py`)**
   - Implements cooldown timers per `(attack_type, src_ip)` to prevent event flooding.
   - Whitelist support for local loopback and gateway addresses.
   - Persistent storage in an embedded SQLite database (`netguard.db`).

---

## Installation & Setup

### Prerequisites
- Python 3.11+
- libpcap (macOS includes BPF/libpcap natively)

### Setup
```bash
# 1. Clone or navigate to the directory
cd /Users/deepanshuagarwal/.gemini/antigravity/scratch/netguard

# 2. Activate virtual environment
source .venv/bin/activate

# 3. Install requirements
pip install -r requirements.txt
```

---

## Running the Application

### 1. Hybrid / Simulation Mode (Recommended for testing without root)
```bash
python netguard/main.py --port 5050
```
Open **`http://127.0.0.1:5050`** in your browser.

### 2. Live Packet Sniffing Mode (Requires elevated privileges)
```bash
sudo .venv/bin/python netguard/main.py --mode live -i en0 --port 5050
```

---

## Testing & Validation

Run the test suite with pytest:

```bash
.venv/bin/pytest tests/ -v
```

All 18 unit and integration tests verify:
- L3/L4 packet decoding (IPv4, IPv6, TCP flags, UDP, ICMP).
- Sliding-window threshold breaches, sub-threshold silence, and window expiry.
- Alert deduplication, cooldown expiry, and SQLite storage.
- REST API health, configuration, and event query endpoints.

---

## Running Test Attack Simulations

Test traffic patterns can be triggered directly from the web interface buttons or via the command line:

```bash
# Via REST API:
python scripts/attack_simulations.py --via-api --attack port_scan
python scripts/attack_simulations.py --via-api --attack syn_flood
python scripts/attack_simulations.py --via-api --attack rst_abuse

# Via raw Scapy socket injection (requires sudo):
sudo python scripts/attack_simulations.py --attack port_scan --target 127.0.0.1
```

---

## Directory Structure

```
netguard/
├── netguard/
│   ├── capture/            # Scapy AsyncSniffer wrapper and queue
│   ├── parsing/            # Packet decoding logic
│   ├── detection/          # Rule detectors (Port Scan, SYN Flood, RST)
│   ├── alerts/             # Cooldown, whitelist, SQLite manager
│   ├── metrics/            # 1 Hz rate aggregator and history buffer
│   ├── web/                # Flask app, Socket.IO, static assets, templates
│   ├── config.py           # Configuration schema
│   ├── models.py           # Typed dataclasses
│   ├── simulation.py       # Test traffic generator
│   └── main.py             # Entry point
├── tests/                  # Pytest test suite
├── scripts/                # CLI simulation script
├── docs/                   # Architecture and technical notes
├── config.yaml             # Threshold configuration
└── requirements.txt        # Dependencies
```
