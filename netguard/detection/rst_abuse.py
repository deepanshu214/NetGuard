"""
RST/FIN Abuse Detector for NetGuard.

Detects malicious or anomalous bursts of TCP RST (Reset) or FIN (Finish) packets
targeting sensitive services (such as SSH 22, HTTP 80, HTTPS 443, RDP 3389)
within a sliding time window.
"""
from collections import defaultdict, deque
from typing import Dict, List, Optional, Set

from netguard.detection.base import BaseDetector
from netguard.models import Alert, PacketEvent


class RstAbuseDetector(BaseDetector):
    def __init__(
        self,
        time_window_seconds: float = 5.0,
        threshold: int = 10,
        target_ports: Optional[List[int]] = None,
        severity: str = "MEDIUM",
        enabled: bool = True,
    ):
        super().__init__(name="RstAbuseDetector", enabled=enabled)
        self.time_window = time_window_seconds
        self.threshold = threshold
        self.target_ports: Set[int] = set(target_ports or [22, 80, 443, 3389, 8080])
        self.severity = severity

        # Source IP -> deque of (timestamp, dst_ip, dst_port, flag_type)
        self.source_history: Dict[str, deque] = defaultdict(deque)

    def on_packet(self, event: PacketEvent, now: Optional[float] = None) -> List[Alert]:
        if not self.enabled or event.proto != "TCP" or not event.dst_port or not event.src_ip:
            return []

        # Only inspect packets targeting monitored sensitive service ports
        if event.dst_port not in self.target_ports:
            return []

        flags = event.tcp_flags.upper()
        has_rst = "R" in flags
        has_fin = "F" in flags

        if not (has_rst or has_fin):
            return []

        current_time = now if now is not None else event.ts
        src_ip = event.src_ip
        dst_ip = event.dst_ip
        dst_port = event.dst_port

        flag_name = "RST" if has_rst else "FIN"
        history = self.source_history[src_ip]
        history.append((current_time, dst_ip, dst_port, flag_name))

        # Evict entries outside sliding window
        cutoff = current_time - self.time_window
        while history and history[0][0] < cutoff:
            history.popleft()

        alerts: List[Alert] = []
        if len(history) >= self.threshold:
            rst_count = sum(1 for e in history if e[3] == "RST")
            fin_count = sum(1 for e in history if e[3] == "FIN")
            targeted_ports = sorted(list({e[2] for e in history}))

            summary = (
                f"Abnormal RST/FIN burst from {src_ip}: {len(history)} packets "
                f"({rst_count} RST, {fin_count} FIN) targeting services {targeted_ports} "
                f"on {dst_ip} within {self.time_window:.1f}s"
            )

            alert = Alert(
                ts=current_time,
                type="RST_ABUSE",
                severity=self.severity,
                src_ip=src_ip,
                dst_ip=dst_ip,
                summary=summary,
                evidence={
                    "total_burst_count": len(history),
                    "rst_count": rst_count,
                    "fin_count": fin_count,
                    "target_ports": targeted_ports,
                    "window_seconds": self.time_window,
                },
            )
            alerts.append(alert)
            history.clear()

        return alerts

    def reset(self):
        self.source_history.clear()
