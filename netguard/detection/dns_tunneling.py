"""
DNS Tunneling and Exfiltration Detector for NetGuard.

Detects covert channels and data exfiltration using DNS protocols (UDP port 53).
Monitors for unusually high frequencies of large, encoded, or anomalous DNS queries
from a single source host within a sliding time window.
"""
from collections import defaultdict, deque
import time
from typing import Dict, List, Optional

from netguard.detection.base import BaseDetector
from netguard.models import Alert, PacketEvent


class DnsTunnelingDetector(BaseDetector):
    """
    Detects data exfiltration and C2 beaconing using DNS tunneling techniques.
    Flags sources generating repetitive large UDP/DNS payloads or excessive query frequencies.
    """

    def __init__(
        self,
        time_window_seconds: float = 4.0,
        query_threshold: int = 15,
        min_payload_len: int = 90,
        severity: str = "HIGH",
        enabled: bool = True,
    ):
        super().__init__(name="DnsTunnelingDetector", enabled=enabled)
        self.time_window = time_window_seconds
        self.query_threshold = query_threshold
        self.min_payload_len = min_payload_len
        self.severity = severity

        # Map: src_ip -> deque of (timestamp, length, dst_port, info)
        self.history: Dict[str, deque] = defaultdict(deque)

    def on_packet(self, event: PacketEvent, now: Optional[float] = None) -> List[Alert]:
        if not self.enabled or event.proto != "UDP":
            return []

        # DNS standard service port 53
        if event.dst_port != 53 and event.src_port != 53:
            return []

        current_time = now if now is not None else event.ts
        src_ip = event.src_ip
        dst_ip = event.dst_ip

        # Check if packet contains large/encoded query characteristic of tunneling
        is_suspicious_dns = event.length >= self.min_payload_len or "DNS" in (event.info or "").upper()
        if not is_suspicious_dns:
            return []

        queue_history = self.history[src_ip]
        queue_history.append((current_time, event.length, dst_ip, event.info or ""))

        # Evict records older than sliding window
        cutoff = current_time - self.time_window
        while queue_history and queue_history[0][0] < cutoff:
            queue_history.popleft()

        alerts: List[Alert] = []
        if len(queue_history) >= self.query_threshold:
            total_bytes = sum(item[1] for item in queue_history)
            avg_len = total_bytes // max(1, len(queue_history))

            summary = (
                f"DNS Tunneling / Data Exfiltration detected from {src_ip}: {len(queue_history)} "
                f"large DNS queries ({total_bytes} bytes total, avg {avg_len} B) sent to {dst_ip} within {self.time_window:.1f}s"
            )

            alert = Alert(
                ts=current_time,
                type="DNS_TUNNELING",
                severity=self.severity,
                src_ip=src_ip,
                dst_ip=dst_ip,
                summary=summary,
                evidence={
                    "dns_queries_count": len(queue_history),
                    "total_exfiltrated_bytes": total_bytes,
                    "avg_payload_length": avg_len,
                    "target_dns_server": dst_ip,
                    "window_seconds": self.time_window,
                    "technique": "Covert DNS Tunnel / Base64 Query Exfiltration",
                },
            )
            alerts.append(alert)
            queue_history.clear()

        return alerts

    def reset(self):
        self.history.clear()
