# NetGuard: Technical Notes & Networking FAQ

This document summarizes the core computer networking and system concepts implemented in NetGuard, covering packet encapsulation, TCP state tracking, intrusion detection rules, and concurrency design.

---

## 1. Network Protocol Fundamentals

### Q1: At which layers of the OSI/TCP-IP model does NetGuard operate?
**Answer:**
NetGuard operates across multiple layers:
- **Layer 2 (Data Link Layer):** Scapy's `AsyncSniffer` captures raw Ethernet frames directly via libpcap/BPF (Berkeley Packet Filter).
- **Layer 3 (Network Layer):** NetGuard's `packet_parser.py` decodes IPv4 and IPv6 packet headers, extracting Source IP, Destination IP, Version, and total packet length.
- **Layer 4 (Transport Layer):** NetGuard decodes TCP and UDP headers, extracting Source Port, Destination Port, TCP Sequence numbers, Acknowledgement numbers, and TCP Control Flags (SYN, ACK, RST, FIN, PSH).
- **Layer 7 (Application Layer):** Flask, WebSockets (Socket.IO), and the Chart.js web dashboard run at the Application Layer to present real-time security telemetry to the network administrator.

---

### Q2: Explain the TCP Three-Way Handshake. How does a SYN Flood exploit it?
**Answer:**
- **Normal Handshake:**
  1. **SYN (Synchronize):** The client sends a TCP packet with the `SYN` flag set and an Initial Sequence Number (`ISN_c`) to the server.
  2. **SYN-ACK:** The server acknowledges by sending a `SYN+ACK` packet with its own sequence number (`ISN_s`) and `ACK = ISN_c + 1`. The connection enters the **SYN_RCVD** state on the server.
  3. **ACK:** The client completes the connection by sending an `ACK` packet with `ACK = ISN_s + 1`. The connection enters the **ESTABLISHED** state.
- **SYN Flood Attack:**
  An attacker transmits a rapid burst of TCP SYN packets (often with spoofed source IPs) and intentionally never transmits the final `ACK`. The server allocates a Transmission Control Block (TCB) in its connection backlog queue for every half-open connection. When the backlog queue fills up, the server can no longer accept legitimate incoming connection requests, causing a **Denial of Service (DoS)**.

---

### Q3: How does NetGuard detect a TCP SYN Flood?
**Answer:**
NetGuard uses two complementary mechanisms in `netguard/detection/syn_flood.py`:
1. **SYN-to-SYN-ACK Ratio:** In healthy traffic, every SYN generates a SYN-ACK (roughly a 1:1 ratio). NetGuard monitors a sliding 2.0-second window. If incoming SYNs exceed 50 and the ratio of SYNs to SYN-ACKs exceeds **4:1**, a **CRITICAL** alert is triggered.
2. **Half-Open Connection Table:** NetGuard maintains a 4-tuple state table `(src_ip, src_port, dst_ip, dst_port)` tracking connections in the half-open state, evicting completed handshakes when the final ACK arrives and flagging unacknowledged stale connections.

---

### Q4: What is the difference between a Vertical and Horizontal Port Scan?
**Answer:**
- **Vertical Port Scan:** An attacker probes multiple destination ports (e.g. 21, 22, 80, 443, 3306) on a **single target IP**. The goal is to discover what services and versions are running on that specific server (reconnaissance).
- **Horizontal Port Scan (Subnet Sweep):** An attacker probes a **single specific port** (e.g., port 22 for SSH or port 445 for SMB) across **many destination IPs** in a subnet. The goal is to find any machine vulnerable to a specific exploit (e.g., EternalBlue or default SSH credentials).
- **NetGuard's Implementation:** In `netguard/detection/port_scan.py`, NetGuard counts unique destination ports and unique destination IPs probed within 3.0 seconds. If `len(unique_ports) >= 15` and `unique_dst_ips == 1`, it classifies the attack as `VERTICAL_PORT_SCAN`. If multiple target IPs are probed, it classifies it as `HORIZONTAL_PORT_SCAN`.

---

### Q5: What are TCP RST and FIN flags, and how does the RST/FIN Abuse detector work?
**Answer:**
- **TCP FIN (Finish):** Used for graceful teardown of an established connection via a 4-way handshake (`FIN` -> `ACK` -> `FIN` -> `ACK`).
- **TCP RST (Reset):** Used to immediately and forcefully terminate an invalid connection or reject connection attempts on a closed port.
- **Abuse Mechanism:**
  1. **Connection Reset Attack:** An attacker injects spoofed RST packets into existing TCP sessions (like SSH or TLS) to abruptly kill user sessions.
  2. **FIN Stealth Scanning:** Attackers send unsolicited FIN packets to ports without a prior handshake. According to RFC 793, closed ports respond with RST while open ports drop the packet, allowing port discovery while attempting to bypass basic stateless packet filters.
- NetGuard monitors sensitive service ports (`22, 80, 443, 3389, 8080`) and triggers an alert if $\ge 10$ RST or FIN packets originate from a single source within 5.0 seconds.

---

## 2. Software Architecture & Concurrency

### Q6: Why did you use Python Threading with a Bounded Queue rather than parsing inside the Sniffer callback?
**Answer:**
If packet parsing or rule evaluation happens directly inside the sniffer callback, any slow detection rule or spike in traffic will block the callback. When the callback is blocked, the operating system's kernel packet buffer overflows, leading to **kernel-level packet drops**.

To prevent this:
1. The `AsyncSniffer` callback does only one thing: non-blocking `put_nowait((raw_packet, timestamp))` into a thread-safe `queue.Queue(maxsize=10000)`.
2. A separate background worker thread (`ParserWorker`) pops from the queue and decodes headers.
3. If traffic exceeds processing capacity, our bounded queue counts drops explicitly, providing backpressure and observability without crashing the kernel capture.

---

### Q7: Isn't Python's Global Interpreter Lock (GIL) a bottleneck for packet processing?
**Answer:**
No, because network packet capture is fundamentally **I/O-bound**.
- Scapy interacts with the underlying C library (`libpcap` on macOS/Linux or `Npcap` on Windows) via system calls. While waiting for packets to arrive from the network interface card (NIC), the thread releases the GIL.
- Furthermore, we apply a kernel-level **Berkeley Packet Filter (BPF)** (`ip or ip6`), which instructs the operating system kernel to discard non-IP frames before they ever enter user space or touch Python.

---

### Q8: Why did you select Flask-SocketIO in `async_mode="threading"` instead of `eventlet` or `gevent`?
**Answer:**
`eventlet` and `gevent` work by "monkey-patching" Python's standard `socket` module with greenlet coroutines. However, Scapy relies on low-level raw socket primitives and OS-level C extensions (`libpcap`). When eventlet monkey-patches sockets, it frequently breaks Scapy's raw packet sniffing and causes deadlock or socket errors. Using standard native Python threads (`async_mode="threading"`) completely avoids this conflict and guarantees rock-solid stability.

---

### Q9: How do your detectors implement sliding time windows efficiently?
**Answer:**
Instead of storing all packets indefinitely, NetGuard uses `collections.deque` keyed by IP address.
Each entry is a tuple `(timestamp, ...)`.
Whenever a new packet arrives at time $t$:
1. The new packet is appended to the right of the deque in $O(1)$ time.
2. An eviction loop inspects the oldest element on the left:
   ```python
   cutoff = current_time - time_window
   while deque_history and deque_history[0][0] < cutoff:
       deque_history.popleft()
   ```
   Because elements are added in chronological order, popping from the left is $O(1)$. This guarantees $O(1)$ amortized sliding-window maintenance and strictly bounded memory.

---

### Q10: How does NetGuard prevent UI alert flooding and Denial of Service on itself?
**Answer:**
1. **Alert Cooldown:** NetGuard's `AlertManager` enforces a cooldown period (e.g. 10.0 seconds) for each `(attack_type, source_ip)` pair. Even if an attacker sends 100,000 packets per second, only one alert is issued per cooldown period, preventing the browser and SQLite database from being swamped.
2. **IP Whitelisting:** Trusted addresses (such as local gateway or DNS) are whitelisted to prevent false positives.
3. **1 Hz Metrics Push:** Rather than streaming per-packet updates to the browser (which would freeze the browser DOM), NetGuard aggregates traffic into 1-second buckets and pushes a single `MetricSnapshot` at 1 Hz over WebSockets.

---

### Q11: What security protections are built into NetGuard's frontend dashboard?
**Answer:**
Packet fields (like IP addresses, payload bytes, and summaries) contain data originating from untrusted network attackers. If inserted into the web page using `innerHTML`, an attacker could craft malicious packet payloads to execute **Cross-Site Scripting (XSS)** in the SOC analyst's browser.
In `dashboard.js`, NetGuard strictly creates DOM nodes and uses `element.textContent = data`, guaranteeing all packet-derived strings are rendered as inert text and never executed as HTML.
