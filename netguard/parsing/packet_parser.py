"""
Packet parser for NetGuard.

This module is responsible for decoding raw Scapy packets into normalized
PacketEvent objects, extracting Layer 3 (IPv4/IPv6) and Layer 4 (TCP/UDP/ICMP)
header fields.
"""
import logging
import queue
import threading
import time
from typing import Callable, Optional
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6

from netguard.models import PacketEvent

logger = logging.getLogger("netguard.parsing")


def parse_scapy_packet(raw_pkt, capture_time: Optional[float] = None) -> Optional[PacketEvent]:
    """
    Decodes raw packet headers into a normalized PacketEvent.
    Extracts L3 (IPv4/IPv6 addresses and lengths) and L4 (TCP flags/ports, UDP, ICMP).
    """
    if capture_time is None:
        capture_time = getattr(raw_pkt, "time", time.time())

    src_ip = None
    dst_ip = None
    ip_ver = None
    length = len(raw_pkt)

    # 1. Decode Layer 3 (Network Layer)
    ttl = None
    if raw_pkt.haslayer(IP):
        ip_layer = raw_pkt[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        ip_ver = 4
        ttl = getattr(ip_layer, "ttl", None)
        if hasattr(ip_layer, "len") and ip_layer.len:
            length = ip_layer.len
    elif raw_pkt.haslayer(IPv6):
        ip6_layer = raw_pkt[IPv6]
        src_ip = ip6_layer.src
        dst_ip = ip6_layer.dst
        ip_ver = 6
        ttl = getattr(ip6_layer, "hlim", None)
        if hasattr(ip6_layer, "plen") and ip6_layer.plen:
            length = ip6_layer.plen + 40  # 40-byte base IPv6 header
    else:
        # Non-IP packet (e.g. raw ARP or L2 protocol); skip for L3/L4 intrusion detection
        return None

    proto = "OTHER"
    src_port = None
    dst_port = None
    tcp_flags = ""
    seq = None
    ack = None
    window = None
    info = ""

    # 2. Decode Layer 4 (Transport Layer)
    if raw_pkt.haslayer(TCP):
        tcp_layer = raw_pkt[TCP]
        proto = "TCP"
        src_port = tcp_layer.sport
        dst_port = tcp_layer.dport
        seq = tcp_layer.seq
        ack = tcp_layer.ack
        window = getattr(tcp_layer, "window", None)
        tcp_flags = str(tcp_layer.flags)
        info = f"[{tcp_flags}] Seq={seq} Ack={ack or 0} Win={window or 0}"
    elif raw_pkt.haslayer(UDP):
        udp_layer = raw_pkt[UDP]
        proto = "UDP"
        src_port = udp_layer.sport
        dst_port = udp_layer.dport
        info = f"{src_port} -> {dst_port} Len={length}"
    elif raw_pkt.haslayer(ICMP):
        proto = "ICMP"
        icmp_layer = raw_pkt[ICMP]
        info = f"Type={getattr(icmp_layer, 'type', 0)} Code={getattr(icmp_layer, 'code', 0)}"

    return PacketEvent(
        ts=float(capture_time),
        src_ip=src_ip,
        dst_ip=dst_ip,
        ip_ver=ip_ver,
        proto=proto,
        src_port=src_port,
        dst_port=dst_port,
        tcp_flags=tcp_flags,
        seq=seq,
        ack=ack,
        ttl=ttl,
        window=window,
        length=length,
        info=info,
    )


class ParserWorker(threading.Thread):
    """
    Background worker thread that consumes raw packet tuples from the capture queue,
    parses them into PacketEvent objects, and dispatches them to registered consumers
    (such as the DetectionEngine and the MetricsAggregator).
    """

    def __init__(
        self,
        packet_queue: queue.Queue,
        on_packet_event: Callable[[PacketEvent], None],
        batch_size: int = 100,
    ):
        super().__init__(name="NetGuard-ParserWorker", daemon=True)
        self.packet_queue = packet_queue
        self.on_packet_event = on_packet_event
        self.batch_size = batch_size
        self._running = False
        self.parsed_count = 0
        self.error_count = 0

    def run(self):
        self._running = True
        logger.info("ParserWorker thread started.")
        while self._running:
            try:
                # Wait up to 0.5s for a packet tuple (raw_pkt, timestamp)
                item = self.packet_queue.get(timeout=0.5)
            except queue.Empty:
                continue

            if item is None:  # Poison pill for shutdown
                self.packet_queue.task_done()
                break

            try:
                raw_pkt, capture_time = item
                event = parse_scapy_packet(raw_pkt, capture_time)
                if event is not None:
                    self.parsed_count += 1
                    self.on_packet_event(event)
            except Exception as e:
                self.error_count += 1
                logger.debug("Packet parsing error: %s", e)
            finally:
                self.packet_queue.task_done()

        logger.info("ParserWorker thread stopped. Total parsed: %d", self.parsed_count)

    def stop(self):
        """Signals the parser thread to terminate."""
        self._running = False
