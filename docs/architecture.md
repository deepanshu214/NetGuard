# NetGuard Architecture & Technical Specification

## 1. System Topology & Data Flow

```
+-------------------------------------------------------------------------+
|                              INGRESS LAYER                              |
|                                                                         |
|  [Network Interface / BPF]                     [Synthetic Simulator]    |
|      (libpcap/Npcap)                                                    |
|             | (Raw Ethernet Frames)                        |            |
|             v                                              |            |
|   [PacketCaptureEngine]                                    |            |
|     (AsyncSniffer)                                         |            |
|             |                                              |            |
|             +---------------------+------------------------+            |
|                                   v                                     |
|                       [Bounded queue.Queue]                             |
|                         (maxsize = 10,000)                              |
+-----------------------------------|-------------------------------------+
                                    v
+-----------------------------------|-------------------------------------+
|                         PARSING & DISPATCH                              |
|                                                                         |
|                         [ParserWorker Thread]                           |
|                    - Decodes IPv4 / IPv6 headers                        |
|                    - Decodes TCP / UDP / ICMP                           |
|                    - Normalizes into PacketEvent                        |
|                                   |                                     |
+-----------------------------------+-------------------------------------+
                                    | Dispatches PacketEvent
             +----------------------+----------------------+
             |                                             |
             v                                             v
+----------------------------+             +------------------------------+
|     DETECTION ENGINE       |             |      METRICS AGGREGATOR      |
|                            |             |                              |
|  - PortScanDetector        |             |  - 1s Sliding Buckets        |
|    (Vertical & Horizontal) |             |  - Throughput (KB/s, pps)    |
|  - SynFloodDetector        |             |  - Protocol Distribution     |
|    (SYN:ACK Ratio > 4:1)   |             |  - Top Talkers (Volume)      |
|  - RstAbuseDetector        |             |  - 60s Ring Buffer           |
|    (Bursts to 22/80/443)   |             +--------------+---------------+
|                            |                            |
| Produces Alert             |                            | 1 Hz Tick
| Objects                    |                            |
+-------------+--------------+                            |
              v                                           |
+-------------+--------------+                            |
|       ALERT MANAGER        |                            |
|                            |                            |
|  - Cooldown Suppression    |                            |
|  - IP Whitelist Filter     |                            |
|  - SQLite (alerts.db)      |                            |
+-------------+--------------+                            |
              |                                           |
              v                                           v
+-------------+-------------------------------------------+---------------+
|                             WEB & API LAYER                             |
|                                                                         |
|                       [Flask-SocketIO Server]                           |
|                         (Threading async mode)                          |
|                                                                         |
|         REST Endpoints                       WebSocket Events           |
|         - GET /api/alerts                    - 'metrics' (1 Hz)         |
|         - GET /api/metrics/history           - 'alert' (on trigger)     |
|         - GET /api/health                    - 'connect' / 'disconnect' |
|         - POST /api/simulate                                            |
+-----------------------------------|-------------------------------------+
                                    v
+-------------------------------------------------------------------------+
|                       CYBERSECURITY SOC DASHBOARD                       |
|                                                                         |
|   - Real-Time Bandwidth & PPS Rolling Line Chart (Chart.js)             |
|   - Protocol Distribution Doughnut Chart                                |
|   - Top Talkers Volume Bar Chart                                        |
|   - Live Color-Coded Security Alert Feed                                |
|   - Deep Forensic Evidence Modal Inspector                             |
|   - 1-Click Interactive Attack Simulation Suite                         |
+-------------------------------------------------------------------------+
```

---

## 2. Core Thread Model

| Thread Name | Priority / Type | Responsibility |
|---|---|---|
| `AsyncSniffer` | Background daemon | Minimal non-blocking capture callback; immediately enqueues `(raw_packet, timestamp)` into the bounded queue. |
| `NetGuard-ParserWorker` | Consumer daemon | Pops items from the bounded queue, parses L3/L4 headers into `PacketEvent` instances, and forwards them to the pipeline. |
| `NetGuard-MetricsBroadcaster`| Timer daemon | Wakes up at 1.0-second intervals (1 Hz), computes bandwidth rates and top talkers, and emits `metrics` over WebSockets. |
| `NetGuard-SimTraffic` | Optional daemon | Generates realistic normal background network traffic (HTTP, DNS, NTP) during simulation/demo mode. |
| `MainThread` | Web server | Runs the Flask-SocketIO HTTP and WebSocket server, serving dashboard assets and handling REST requests. |

---

## 3. Data Schema & Contracts

### 3.1 PacketEvent
```json
{
  "ts": 1758450000.12,
  "src_ip": "192.168.1.189",
  "dst_ip": "192.168.1.10",
  "ip_ver": 4,
  "proto": "TCP",
  "src_port": 54321,
  "dst_port": 80,
  "tcp_flags": "S",
  "seq": 1000,
  "ack": null,
  "length": 64,
  "iface": "en0"
}
```

### 3.2 Alert
```json
{
  "id": "e7b0a51c-c377-4cf0-a2bc-33c914bf8206",
  "ts": 1758450001.45,
  "type": "PORT_SCAN",
  "severity": "HIGH",
  "src_ip": "192.168.1.189",
  "dst_ip": "192.168.1.10",
  "summary": "Vertical port scan detected from 192.168.1.189: 20 unique ports probed on target 192.168.1.10 within 3.0s",
  "evidence": {
    "scan_pattern": "VERTICAL_PORT_SCAN",
    "unique_ports_count": 20,
    "target_hosts_count": 1,
    "sample_ports": [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433],
    "window_seconds": 3.0
  }
}
```

### 3.3 MetricSnapshot (Pushed at 1 Hz)
```json
{
  "ts": 1758450002.00,
  "pps": 145,
  "bps": 92800,
  "kbps": 742.4,
  "total_packets": 3200,
  "total_bytes": 2048000,
  "protocol_counts": { "TCP": 120, "UDP": 20, "ICMP": 5, "OTHER": 0 },
  "top_talkers": [
    { "ip": "192.168.1.189", "packets": 80, "bytes": 51200 },
    { "ip": "192.168.1.10", "packets": 40, "bytes": 25600 }
  ],
  "queue_size": 2,
  "drop_count": 0
}
```
