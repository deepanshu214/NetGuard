import time
from collections import deque
from typing import List, Optional, Dict
from netguard.detection.base import BaseDetector
from netguard.models import PacketEvent, Alert

class IcmpFloodDetector(BaseDetector):
    """
    Detects ICMP flood attacks (ping floods) and ICMP sweeps (subnet scanning).
    Triggers when a single source IP sends a high volume of ICMP packets
    within a short time window.
    """
    def __init__(self, time_window_seconds: float = 3.0, threshold: int = 30, severity: str = 'MEDIUM', enabled: bool = True):
        super().__init__(name="IcmpFloodDetector", enabled=enabled)
        self.time_window_seconds = time_window_seconds
        self.threshold = threshold
        self.severity = severity
        
        # Maps src_ip -> deque of (timestamp, dst_ip)
        self.windows: Dict[str, deque] = {}

    def on_packet(self, event: PacketEvent, now: Optional[float] = None) -> List[Alert]:
        alerts = []
        if not self.enabled or event.proto != 'ICMP':
            return alerts

        current_time = now if now is not None else time.time()
        
        if event.src_ip not in self.windows:
            self.windows[event.src_ip] = deque()
            
        window = self.windows[event.src_ip]
        window.append((current_time, event.dst_ip))
        
        # Clean up old packets
        while window and window[0][0] < current_time - self.time_window_seconds:
            window.popleft()
            
        if len(window) >= self.threshold:
            # We have a flood or sweep
            dst_ips = {dst_ip for _, dst_ip in window if dst_ip}
            unique_targets = len(dst_ips)
            
            classification = "ICMP_SWEEP" if unique_targets >= 10 else "ICMP_FLOOD"
            
            alerts.append(Alert(
                type=classification,
                severity=self.severity,
                src_ip=event.src_ip,
                dst_ip=event.dst_ip, # The last target
                summary=f"{classification} detected from {event.src_ip} ({len(window)} pkts to {unique_targets} targets in {self.time_window_seconds}s)",
                evidence={
                    "icmp_count": len(window),
                    "source_ip": event.src_ip,
                    "window_seconds": self.time_window_seconds,
                    "unique_targets": unique_targets,
                    "classification": classification
                }
            ))
            # Clear the window to avoid continuous spamming of alerts
            window.clear()
            
        return alerts

    def reset(self):
        self.windows.clear()
