"""
SYN Flood Detector for NetGuard.

Detects TCP SYN Flood Denial of Service (DoS) attacks by monitoring the ratio
of incoming unacknowledged SYN packets to outgoing SYN-ACK responses, and tracking
uncompleted half-open TCP connections in a sliding time window.
"""
from collections import defaultdict, deque
from typing import Dict, List, Optional, Tuple

from netguard.detection.base import BaseDetector
from netguard.models import Alert, PacketEvent


class SynFloodDetector(BaseDetector):
    def __init__(
        self,
        time_window_seconds: float = 2.0,
        syn_threshold: int = 50,
        syn_ack_ratio_threshold: float = 4.0,
        half_open_timeout: float = 5.0,
        severity: str = "CRITICAL",
        enabled: bool = True,
    ):
        super().__init__(name="SynFloodDetector", enabled=enabled)
        self.time_window = time_window_seconds
        self.syn_threshold = syn_threshold
        self.ratio_threshold = syn_ack_ratio_threshold
        self.half_open_timeout = half_open_timeout
        self.severity = severity

        # Target IP -> deque of (timestamp, is_syn, is_synack, src_ip)
        self.target_history: Dict[str, deque] = defaultdict(deque)

        # 4-tuple tracking: (src_ip, sport, dst_ip, dport) -> (timestamp, state)
        # States: "SYN_RCVD", "ESTABLISHED"
        self.half_open_table: Dict[Tuple[str, int, str, int], float] = {}

    def on_packet(self, event: PacketEvent, now: Optional[float] = None) -> List[Alert]:
        if not self.enabled or event.proto != "TCP" or not event.dst_ip:
            return []

        current_time = now if now is not None else event.ts
        flags = event.tcp_flags.upper()
        alerts: List[Alert] = []

        is_syn = "S" in flags and "A" not in flags
        is_synack = "S" in flags and "A" in flags
        is_ack = "A" in flags and "S" not in flags

        tuple_key = (
            event.src_ip,
            event.src_port or 0,
            event.dst_ip,
            event.dst_port or 0,
        )
        reverse_key = (
            event.dst_ip,
            event.dst_port or 0,
            event.src_ip,
            event.src_port or 0,
        )

        # Track TCP 3-way handshake state
        if is_syn:
            self.half_open_table[tuple_key] = current_time
        elif is_synack:
            pass
        elif is_ack:
            # Check if this ACK completes a pending handshake
            if reverse_key in self.half_open_table:
                del self.half_open_table[reverse_key]

        # Purge stale half-open connections older than timeout
        stale_keys = [
            k for k, start_ts in self.half_open_table.items()
            if current_time - start_ts > self.half_open_timeout
        ]
        for k in stale_keys:
            del self.half_open_table[k]

        if is_syn or is_synack:
            # For SYN, victim is dst_ip; for SYN-ACK, victim server responding is src_ip
            victim_ip = event.dst_ip if is_syn else event.src_ip
            history = self.target_history[victim_ip]
            history.append((current_time, is_syn, is_synack, event.src_ip))

            # Evict entries older than sliding window
            cutoff = current_time - self.time_window
            while history and history[0][0] < cutoff:
                history.popleft()

            # Count total SYNs and SYN-ACKs in current window
            syn_count = sum(1 for entry in history if entry[1])
            synack_count = sum(1 for entry in history if entry[2])
            ratio = syn_count / max(1, synack_count)

            # Check if attack criteria met
            if syn_count >= self.syn_threshold and ratio >= self.ratio_threshold:
                # Identify dominant attack source IP(s)
                sources = [entry[3] for entry in history if entry[1]]
                attacker_ip = max(set(sources), key=sources.count) if sources else "unknown"

                summary = (
                    f"TCP SYN Flood DoS attacking target {victim_ip}: {syn_count} SYNs vs "
                    f"{synack_count} SYN-ACKs (ratio: {ratio:.1f}:1, {len(self.half_open_table)} half-open) "
                    f"in {self.time_window:.1f}s"
                )

                alert = Alert(
                    ts=current_time,
                    type="SYN_FLOOD",
                    severity=self.severity,
                    src_ip=attacker_ip,
                    dst_ip=victim_ip,
                    summary=summary,
                    evidence={
                        "syn_count": syn_count,
                        "synack_count": synack_count,
                        "syn_ratio": round(ratio, 2),
                        "half_open_connections": len(self.half_open_table),
                        "window_seconds": self.time_window,
                        "dominant_attacker_ip": attacker_ip,
                    },
                )
                alerts.append(alert)
                history.clear()

        return alerts

    def reset(self):
        self.target_history.clear()
        self.half_open_table.clear()
