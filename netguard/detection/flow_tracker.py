"""
TCP Connection and Flow State Machine Tracker for NetGuard.

Maintains an in-memory connection table tracking TCP 4-tuple flows and their
handshake states (SYN_SENT, SYN_RCVD, ESTABLISHED, FIN_WAIT, CLOSED, HALF_OPEN).
"""
from collections import OrderedDict
import threading
import time
from typing import Dict, List, Optional, Tuple

from netguard.models import PacketEvent, TCPFlow


class TCPFlowTracker:
    """
    Stateful TCP flow tracker.
    Models the standard RFC 793 TCP connection lifecycle.
    """

    def __init__(self, max_flows: int = 1000, half_open_timeout: float = 5.0):
        self.max_flows = max_flows
        self.half_open_timeout = half_open_timeout
        self._lock = threading.Lock()
        # Key: (min(endpoint1, endpoint2), max(endpoint1, endpoint2))
        self.flows: Dict[Tuple, TCPFlow] = OrderedDict()

    def _make_key(self, event: PacketEvent) -> Tuple:
        ep1 = (event.src_ip, event.src_port or 0)
        ep2 = (event.dst_ip, event.dst_port or 0)
        return (min(ep1, ep2), max(ep1, ep2))

    def on_packet(self, event: PacketEvent, now: Optional[float] = None):
        if event.proto != "TCP" or not event.src_port or not event.dst_port:
            return

        current_time = now if now is not None else event.ts
        flags = event.tcp_flags.upper()
        key = self._make_key(event)

        with self._lock:
            flow = self.flows.get(key)
            if not flow:
                # New connection initiated
                flow_id = f"{event.src_ip}:{event.src_port} -> {event.dst_ip}:{event.dst_port}"
                initial_state = "SYN_SENT" if "S" in flags and "A" not in flags else "ESTABLISHED"
                flow = TCPFlow(
                    flow_id=flow_id,
                    src_ip=event.src_ip,
                    src_port=event.src_port,
                    dst_ip=event.dst_ip,
                    dst_port=event.dst_port,
                    state=initial_state,
                    start_time=current_time,
                    last_seen=current_time,
                    packet_count=1,
                    byte_count=event.length,
                )
                self.flows[key] = flow
                if len(self.flows) > self.max_flows:
                    self.flows.popitem(last=False)
            else:
                # Update existing flow
                flow.packet_count += 1
                flow.byte_count += event.length
                flow.last_seen = current_time

                # State machine transitions
                if "R" in flags:
                    flow.state = "CLOSED"
                elif "F" in flags:
                    flow.state = "FIN_WAIT"
                elif "S" in flags and "A" in flags:
                    flow.state = "SYN_RCVD"
                elif "A" in flags and flow.state in ("SYN_RCVD", "SYN_SENT"):
                    flow.state = "ESTABLISHED"

                # Check for half-open timeout
                if flow.state in ("SYN_SENT", "SYN_RCVD"):
                    if current_time - flow.start_time > self.half_open_timeout:
                        flow.state = "HALF_OPEN"

    def get_flows(self, limit: int = 50) -> List[dict]:
        """Returns list of active flows sorted by recency."""
        with self._lock:
            # Clean up closed flows older than 30s
            now = time.time()
            stale_keys = [
                k for k, f in self.flows.items()
                if f.state == "CLOSED" and (now - f.last_seen > 30.0)
            ]
            for k in stale_keys:
                del self.flows[k]

            flows_list = list(self.flows.values())
            # Return most recently updated flows first
            flows_list.sort(key=lambda f: f.last_seen, reverse=True)
            return [f.to_dict() for f in flows_list[:limit]]

    def get_active_count(self) -> int:
        with self._lock:
            return sum(1 for f in self.flows.values() if f.state not in ("CLOSED",))
