"""Core data models and data contracts for NetGuard."""
from dataclasses import dataclass, field, asdict
from typing import Dict, Any, List, Optional
import uuid
import time


@dataclass
class PacketEvent:
    """Represents a normalized, decoded network packet."""
    ts: float                      # Packet capture timestamp (seconds since epoch)
    src_ip: str                    # Source IPv4 or IPv6 address
    dst_ip: str                    # Destination IPv4 or IPv6 address
    ip_ver: int                    # 4 or 6
    proto: str                     # "TCP", "UDP", "ICMP", "OTHER"
    src_port: Optional[int] = None # Source port (TCP/UDP)
    dst_port: Optional[int] = None # Destination port (TCP/UDP)
    tcp_flags: str = ""            # e.g., "S", "SA", "FA", "R", "PA"
    seq: Optional[int] = None      # TCP sequence number
    ack: Optional[int] = None      # TCP acknowledgement number
    ttl: Optional[int] = None      # Time To Live (IP Header)
    window: Optional[int] = None   # TCP Window Size
    length: int = 0                # Total packet length in bytes
    info: str = ""                 # Descriptive summary / flags info
    iface: str = "default"         # Ingress network interface

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Alert:
    """Security alert raised by an intrusion detection rule."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    ts: float = field(default_factory=time.time)
    type: str = "GENERIC_ALERT"    # "PORT_SCAN", "SYN_FLOOD", "RST_ABUSE", "ICMP_FLOOD"
    severity: str = "MEDIUM"       # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    src_ip: str = ""
    dst_ip: str = ""
    summary: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class TCPFlow:
    """Represents an active TCP connection 4-tuple and its handshake state."""
    flow_id: str                   # "src:sport -> dst:dport"
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    state: str                     # "SYN_SENT", "SYN_RCVD", "ESTABLISHED", "FIN_WAIT", "CLOSED", "HALF_OPEN"
    start_time: float
    last_seen: float
    packet_count: int = 1
    byte_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "flow_id": self.flow_id,
            "src_ip": self.src_ip,
            "src_port": self.src_port,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "state": self.state,
            "start_time": self.start_time,
            "last_seen": self.last_seen,
            "duration_s": round(self.last_seen - self.start_time, 2),
            "packet_count": self.packet_count,
            "byte_count": self.byte_count,
        }


@dataclass
class TopTalker:
    """Traffic volume associated with an IP address."""
    ip: str
    packet_count: int
    byte_count: int


@dataclass
class MetricSnapshot:
    """1-second rolling metrics snapshot pushed to the web client."""
    ts: float
    pps: int                       # Packets per second in this interval
    bps: int                       # Bytes per second in this interval
    kbps: float                    # Kilobits per second
    total_packets: int             # Cumulative packet count since start
    total_bytes: int               # Cumulative byte count since start
    protocol_counts: Dict[str, int]# {"TCP": 120, "UDP": 45, "ICMP": 2, "OTHER": 0}
    top_talkers: List[Dict[str, Any]] # [{"ip": "...", "packets": 80, "bytes": 45000}]
    active_flows_count: int = 0    # Current active TCP connections
    queue_size: int = 0            # Packets currently queued in buffer
    drop_count: int = 0            # Dropped packets due to buffer overflow
    avg_packet_size: int = 0       # Average bytes per packet in this interval
    baseline_upper_pps: int = 0    # Dynamic statistical ceiling (mean + 2*sigma)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
