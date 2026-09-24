import time
from collections import deque, Counter
from typing import List, Optional, Dict, Tuple
from netguard.detection.base import BaseDetector
from netguard.models import PacketEvent, Alert

class UdpFloodDetector(BaseDetector):
    """
    Detects UDP flood attacks and potential DNS amplification attempts.
    Triggers when a single source IP sends a high volume of UDP packets
    within a short time window.
    """
    def __init__(self, time_window_seconds: float = 3.0, threshold: int = 40, severity: str = 'HIGH', enabled: bool = True):
        super().__init__(name="UdpFloodDetector", enabled=enabled)
        self.time_window_seconds = time_window_seconds
        self.threshold = threshold
        self.severity = severity
        
        # Maps src_ip -> deque of (timestamp, dst_port)
        self.windows: Dict[str, deque] = {}

    def on_packet(self, event: PacketEvent, now: Optional[float] = None) -> List[Alert]:
        alerts = []
        if not self.enabled or event.proto != 'UDP':
            return alerts

        current_time = now if now is not None else time.time()
        
        if event.src_ip not in self.windows:
            self.windows[event.src_ip] = deque()
            
        window = self.windows[event.src_ip]
        window.append((current_time, event.dst_port))
        
        # Clean up old packets
        while window and window[0][0] < current_time - self.time_window_seconds:
            window.popleft()
            
        if len(window) >= self.threshold:
            # We have a flood
            ports = [port for _, port in window if port is not None]
            port_counts = Counter(ports)
            top_dst_ports = [port for port, count in port_counts.most_common(3)]
            
            alerts.append(Alert(
                type="UDP_FLOOD",
                severity=self.severity,
                src_ip=event.src_ip,
                dst_ip=event.dst_ip,
                summary=f"UDP flood detected from {event.src_ip} ({len(window)} pkts in {self.time_window_seconds}s)",
                evidence={
                    "udp_count": len(window),
                    "source_ip": event.src_ip,
                    "window_seconds": self.time_window_seconds,
                    "top_dst_ports": top_dst_ports
                }
            ))
            # Clear the window to avoid continuous spamming of alerts
            window.clear()
            
        return alerts

    def reset(self):
        self.windows.clear()
