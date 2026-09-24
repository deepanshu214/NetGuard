"""
Metrics Aggregator for NetGuard.

Collects packet and bandwidth statistics in 1-second rolling intervals,
computes top network talkers, protocol breakdowns, and maintains a 60-second
history ring buffer for live Chart.js rendering.
"""
from collections import defaultdict, deque
import threading
import time
from typing import Any, Callable, Dict, List, Optional

from netguard.models import MetricSnapshot, PacketEvent


class MetricsAggregator:
    """
    Computes real-time bandwidth and traffic metrics at 1 Hz frequency.
    """

    def __init__(
        self,
        history_len: int = 60,
        on_snapshot: Optional[Callable[[MetricSnapshot], None]] = None,
    ):
        self.history_len = history_len
        self.on_snapshot = on_snapshot
        self._lock = threading.Lock()

        # Cumulative totals since engine startup
        self.total_packets = 0
        self.total_bytes = 0

        # Current interval accumulators
        self.current_interval_start = time.time()
        self.interval_packets = 0
        self.interval_bytes = 0
        self.protocol_counts: Dict[str, int] = defaultdict(int)
        self.ip_traffic: Dict[str, Dict[str, int]] = defaultdict(lambda: {"packets": 0, "bytes": 0})

        # Ring buffer of historical 1s snapshots (for client reconnects)
        self.history: deque[MetricSnapshot] = deque(maxlen=history_len)

        # Health indicators
        self.queue_size_supplier: Optional[Callable[[], int]] = None
        self.drop_count_supplier: Optional[Callable[[], int]] = None

    def on_packet(self, event: PacketEvent):
        """Processes an incoming packet into current interval metrics."""
        with self._lock:
            self.total_packets += 1
            self.total_bytes += event.length

            self.interval_packets += 1
            self.interval_bytes += event.length
            self.protocol_counts[event.proto] += 1

            if event.src_ip:
                stats = self.ip_traffic[event.src_ip]
                stats["packets"] += 1
                stats["bytes"] += event.length

    def tick(self, now: Optional[float] = None) -> MetricSnapshot:
        """
        Called once per second (1 Hz) to close the current interval,
        calculate rates, publish a snapshot, and reset interval counters.
        """
        current_time = now if now is not None else time.time()

        with self._lock:
            elapsed = max(0.001, current_time - self.current_interval_start)
            pps = int(self.interval_packets / elapsed)
            bps = int(self.interval_bytes / elapsed)
            kbps = round((bps * 8) / 1000.0, 2)

            # Extract top 5 talkers by byte volume
            sorted_talkers = sorted(
                [
                    {"ip": ip, "packets": data["packets"], "bytes": data["bytes"]}
                    for ip, data in self.ip_traffic.items()
                ],
                key=lambda x: x["bytes"],
                reverse=True,
            )[:5]

            # Current queue and drop statistics
            q_size = self.queue_size_supplier() if self.queue_size_supplier else 0
            drop_count = self.drop_count_supplier() if self.drop_count_supplier else 0

            # Calculate average packet size (bytes) in this interval
            avg_size = int(self.interval_bytes / max(1, self.interval_packets))

            # Dynamic Statistical Baseline Corridor (rolling mean + 2*sigma)
            if len(self.history) >= 5:
                recent_pps = [s.pps for s in list(self.history)[-30:]]
                mean_pps = sum(recent_pps) / len(recent_pps)
                variance = sum((x - mean_pps) ** 2 for x in recent_pps) / len(recent_pps)
                std_pps = variance ** 0.5
                baseline_upper = int(mean_pps + (2.0 * max(6.0, std_pps)))
            else:
                baseline_upper = max(50, int(pps * 1.6))

            snapshot = MetricSnapshot(
                ts=current_time,
                pps=pps,
                bps=bps,
                kbps=kbps,
                total_packets=self.total_packets,
                total_bytes=self.total_bytes,
                protocol_counts=dict(self.protocol_counts),
                top_talkers=sorted_talkers,
                queue_size=q_size,
                drop_count=drop_count,
                avg_packet_size=avg_size,
                baseline_upper_pps=baseline_upper,
            )

            # Store in ring buffer
            self.history.append(snapshot)

            # Reset interval accumulators
            self.current_interval_start = current_time
            self.interval_packets = 0
            self.interval_bytes = 0
            self.protocol_counts.clear()
            self.ip_traffic.clear()

        if self.on_snapshot:
            try:
                self.on_snapshot(snapshot)
            except Exception:
                pass

        return snapshot

    def reset_counters(self):
        """Resets cumulative packet and byte totals (useful for session resets)."""
        with self._lock:
            self.total_packets = 0
            self.total_bytes = 0
            self.interval_packets = 0
            self.interval_bytes = 0
            self.protocol_counts.clear()
            self.ip_traffic.clear()
            self.history.clear()

    def get_history(self) -> List[Dict[str, Any]]:
        """Returns the past 60 seconds of metric snapshots for chart pre-filling."""
        with self._lock:
            return [s.to_dict() for s in self.history]
