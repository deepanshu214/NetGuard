"""
Port Scan Detector for NetGuard.

Detects rapid probing of multiple destination ports from a single source IP
within a sliding time window (e.g. >= 15 unique ports within 3.0 seconds).
Distinguishes between:
- Vertical Port Scan: Probing multiple ports on a single target IP.
- Horizontal Port Scan: Probing one or few ports across multiple target IPs (subnet sweep).
"""
import time
from collections import defaultdict, deque
from typing import Dict, List, Optional, Tuple

from netguard.detection.base import BaseDetector
from netguard.models import Alert, PacketEvent


class PortScanDetector(BaseDetector):
    def __init__(
        self,
        time_window_seconds: float = 3.0,
        unique_port_threshold: int = 15,
        severity: str = "HIGH",
        enabled: bool = True,
    ):
        super().__init__(name="PortScanDetector", enabled=enabled)
        self.time_window = time_window_seconds
        self.port_threshold = unique_port_threshold
        self.severity = severity
        # Map: src_ip -> deque of (timestamp, dst_ip, dst_port)
        self.history: Dict[str, deque] = defaultdict(deque)

    def on_packet(self, event: PacketEvent, now: Optional[float] = None) -> List[Alert]:
        if not self.enabled or event.proto not in ("TCP", "UDP") or not event.dst_port or not event.src_ip:
            return []

        current_time = now if now is not None else event.ts
        src_ip = event.src_ip
        dst_ip = event.dst_ip
        dst_port = event.dst_port

        queue_history = self.history[src_ip]
        # Append new probe
        queue_history.append((current_time, dst_ip, dst_port))

        # Evict entries older than sliding time window
        cutoff = current_time - self.time_window
        while queue_history and queue_history[0][0] < cutoff:
            queue_history.popleft()

        # Check unique destination ports probed
        unique_ports = {entry[2] for entry in queue_history}
        unique_dst_ips = {entry[1] for entry in queue_history}

        alerts: List[Alert] = []

        if len(unique_ports) >= self.port_threshold:
            # Classify scan pattern
            if len(unique_dst_ips) == 1:
                pattern = "VERTICAL_PORT_SCAN"
                summary = (
                    f"Vertical port scan detected from {src_ip}: {len(unique_ports)} unique ports "
                    f"probed on target {dst_ip} within {self.time_window:.1f}s"
                )
            else:
                pattern = "HORIZONTAL_PORT_SCAN"
                summary = (
                    f"Horizontal port scan detected from {src_ip}: {len(unique_ports)} unique ports "
                    f"probed across {len(unique_dst_ips)} hosts within {self.time_window:.1f}s"
                )

            alert = Alert(
                ts=current_time,
                type="PORT_SCAN",
                severity=self.severity,
                src_ip=src_ip,
                dst_ip=dst_ip,
                summary=summary,
                evidence={
                    "scan_pattern": pattern,
                    "unique_ports_count": len(unique_ports),
                    "target_hosts_count": len(unique_dst_ips),
                    "sample_ports": sorted(list(unique_ports))[:15],
                    "window_seconds": self.time_window,
                },
            )
            alerts.append(alert)
            # Reset queue after trigger to prevent duplicate firing on every single following packet
            queue_history.clear()

        return alerts

    def reset(self):
        self.history.clear()
