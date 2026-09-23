"""
PCAP and forensic report export module for NetGuard.

Enables downloading captured traffic as a valid .pcap file (for Wireshark)
and exporting alert logs as CSV/JSON for lab reports.
"""
from collections import deque
import csv
import io
import logging
import threading
import time
from typing import List, Optional
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.utils import wrpcap

from netguard.models import PacketEvent

logger = logging.getLogger("netguard.recorder")


class PacketRecorder:
    """Maintains a rolling ring buffer of captured packets for PCAP export."""

    def __init__(self, maxlen: int = 500):
        self.maxlen = maxlen
        self._lock = threading.Lock()
        self.buffer = deque(maxlen=maxlen)

    def record_raw(self, raw_pkt):
        """Records a real Scapy packet object."""
        with self._lock:
            self.buffer.append(raw_pkt)

    def record_event(self, event: PacketEvent):
        """Synthesizes a minimal Scapy packet from PacketEvent if raw packet not available."""
        try:
            pkt = None
            if event.proto == "TCP":
                flags = event.tcp_flags or "S"
                pkt = IP(src=event.src_ip, dst=event.dst_ip) / TCP(
                    sport=event.src_port or 1024,
                    dport=event.dst_port or 80,
                    flags=flags,
                    seq=event.seq or 1000,
                    ack=event.ack or 0,
                )
            elif event.proto == "UDP":
                pkt = IP(src=event.src_ip, dst=event.dst_ip) / UDP(
                    sport=event.src_port or 1024,
                    dport=event.dst_port or 53,
                )
            elif event.proto == "ICMP":
                pkt = IP(src=event.src_ip, dst=event.dst_ip) / ICMP()

            if pkt is not None:
                pkt.time = event.ts
                with self._lock:
                    self.buffer.append(pkt)
        except Exception as e:
            logger.debug("Could not synthesize packet for recorder: %s", e)

    def export_pcap_bytes(self) -> bytes:
        """Serializes buffered packets into standard PCAP binary format."""
        import os
        import tempfile

        with self._lock:
            pkts = list(self.buffer)

        if not pkts:
            # If buffer is empty, generate a single dummy packet so Wireshark can open it
            pkts = [IP(src="127.0.0.1", dst="127.0.0.1") / TCP(dport=80, flags="S")]

        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
            tmp_path = tmp.name

        try:
            wrpcap(tmp_path, pkts)
            with open(tmp_path, "rb") as f:
                return f.read()
        finally:
            if os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except Exception:
                    pass

    def get_count(self) -> int:
        with self._lock:
            return len(self.buffer)


def export_alerts_csv(alerts: List[dict]) -> str:
    """Formats alert records as a standard CSV string."""
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Alert ID", "Timestamp", "Severity", "Attack Type", "Source IP", "Target IP", "Summary"])

    for a in alerts:
        t_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(a.get("ts", time.time())))
        writer.writerow([
            a.get("id", ""),
            t_str,
            a.get("severity", ""),
            a.get("type", ""),
            a.get("src_ip", ""),
            a.get("dst_ip", ""),
            a.get("summary", ""),
        ])

    return output.getvalue()
