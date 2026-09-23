"""Packet capture engine using Scapy AsyncSniffer and bounded queue."""
import logging
import queue
import threading
import time
from typing import Optional, Tuple
from scapy.all import AsyncSniffer, conf

logger = logging.getLogger("netguard.capture")


class PacketCaptureEngine:
    """
    Captures live packets from the network interface using Scapy AsyncSniffer.
    Ensures zero packet parsing inside the capture callback by immediately
    enqueuing (packet, timestamp) tuples into a bounded thread-safe queue.
    """

    def __init__(
        self,
        packet_queue: queue.Queue,
        interface: str = "auto",
        bpf_filter: str = "ip or ip6",
        packet_recorder=None,
    ):
        self.packet_queue = packet_queue
        self.interface = self._resolve_interface(interface)
        self.bpf_filter = bpf_filter
        self.packet_recorder = packet_recorder
        self.sniffer: Optional[AsyncSniffer] = None
        self.is_running = False
        self.dropped_packets = 0
        self.total_captured = 0

    def _resolve_interface(self, iface_setting: str) -> Optional[str]:
        """Resolves 'auto' or checks if the specified interface exists."""
        if not iface_setting or iface_setting.lower() == "auto":
            try:
                selected = str(conf.iface)
                logger.info("Auto-detected default network interface: %s", selected)
                return selected
            except Exception as e:
                logger.warning("Could not auto-detect interface (%s), using Scapy default", e)
                return None
        return iface_setting

    def _packet_callback(self, raw_pkt):
        """Minimal non-blocking callback invoked by AsyncSniffer per packet."""
        capture_time = getattr(raw_pkt, "time", time.time())
        self.total_captured += 1
        if self.packet_recorder:
            self.packet_recorder.record_raw(raw_pkt)
        try:
            # Non-blocking put: if queue is full, increment drop counter
            self.packet_queue.put_nowait((raw_pkt, capture_time))
        except queue.Full:
            self.dropped_packets += 1

    def start(self):
        """Starts asynchronous packet capture in a background thread."""
        if self.is_running:
            return

        logger.info(
            "Starting AsyncSniffer on interface '%s' with filter '%s'",
            self.interface,
            self.bpf_filter,
        )
        try:
            kwargs = {
                "prn": self._packet_callback,
                "store": False,
                "filter": self.bpf_filter,
            }
            if self.interface:
                kwargs["iface"] = self.interface

            self.sniffer = AsyncSniffer(**kwargs)
            self.sniffer.start()
            self.is_running = True
            logger.info("AsyncSniffer successfully started.")
        except PermissionError:
            logger.error("Permission denied: Packet sniffing requires root/sudo privileges.")
            raise
        except Exception as e:
            logger.error("Failed to start sniffer: %s", e)
            raise

    def stop(self):
        """Stops packet capture gracefully."""
        if not self.is_running:
            return
        logger.info("Stopping AsyncSniffer...")
        self.is_running = False
        if self.sniffer:
            try:
                self.sniffer.stop()
            except Exception as e:
                logger.warning("Error stopping AsyncSniffer: %s", e)
        logger.info(
            "Sniffer stopped. Total captured: %d, Dropped: %d",
            self.total_captured,
            self.dropped_packets,
        )

    def get_stats(self) -> dict:
        """Returns capture health metrics."""
        return {
            "is_running": self.is_running,
            "interface": self.interface or str(conf.iface),
            "total_captured": self.total_captured,
            "dropped_packets": self.dropped_packets,
            "current_queue_size": self.packet_queue.qsize(),
        }
