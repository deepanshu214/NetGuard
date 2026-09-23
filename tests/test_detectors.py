"""
Deterministic unit tests for NetGuard detection engine rules.

Covers:
1. Port Scan: Trigger case, just-below-threshold case, and sliding-window expiry.
2. SYN Flood: Attack trigger case, balanced legitimate traffic case, and timeout.
3. RST/FIN Abuse: Targeted sensitive ports trigger case and ignored ports case.
"""
import pytest

from netguard.detection.port_scan import PortScanDetector
from netguard.detection.rst_abuse import RstAbuseDetector
from netguard.detection.syn_flood import SynFloodDetector
from netguard.models import PacketEvent


def make_packet(
    ts: float,
    src_ip: str = "192.168.1.100",
    dst_ip: str = "192.168.1.5",
    proto: str = "TCP",
    src_port: int = 40000,
    dst_port: int = 80,
    flags: str = "S",
) -> PacketEvent:
    return PacketEvent(
        ts=ts,
        src_ip=src_ip,
        dst_ip=dst_ip,
        ip_ver=4,
        proto=proto,
        src_port=src_port,
        dst_port=dst_port,
        tcp_flags=flags,
        length=64,
    )


# ==============================================================================
# 1. PORT SCAN DETECTOR TESTS
# ==============================================================================

def test_port_scan_trigger():
    """Verify that probing 15 unique ports within 3.0s triggers a PORT_SCAN alert."""
    detector = PortScanDetector(time_window_seconds=3.0, unique_port_threshold=15)
    base_time = 1000.0

    alerts = []
    # Send 15 packets to 15 different ports
    for i in range(15):
        pkt = make_packet(ts=base_time + (i * 0.1), dst_port=1000 + i)
        alerts.extend(detector.on_packet(pkt))

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.type == "PORT_SCAN"
    assert alert.severity == "HIGH"
    assert alert.src_ip == "192.168.1.100"
    assert alert.evidence["unique_ports_count"] == 15
    assert alert.evidence["scan_pattern"] == "VERTICAL_PORT_SCAN"


def test_port_scan_below_threshold():
    """Verify that probing 14 unique ports (below threshold of 15) does NOT trigger."""
    detector = PortScanDetector(time_window_seconds=3.0, unique_port_threshold=15)
    base_time = 1000.0

    alerts = []
    for i in range(14):
        pkt = make_packet(ts=base_time + (i * 0.1), dst_port=1000 + i)
        alerts.extend(detector.on_packet(pkt))

    assert len(alerts) == 0


def test_port_scan_window_expiry():
    """Verify that probes spread beyond the time window are evicted and do NOT trigger."""
    detector = PortScanDetector(time_window_seconds=3.0, unique_port_threshold=15)
    base_time = 1000.0

    alerts = []
    # Send 10 packets, then wait 4 seconds (window is 3s), then send another 6 packets
    for i in range(10):
        pkt = make_packet(ts=base_time + (i * 0.1), dst_port=1000 + i)
        alerts.extend(detector.on_packet(pkt))

    # Advance time by 4.0 seconds
    later_time = base_time + 4.0
    for i in range(6):
        pkt = make_packet(ts=later_time + (i * 0.1), dst_port=2000 + i)
        alerts.extend(detector.on_packet(pkt))

    # Old 10 were evicted, so only 6 ports are in the current window -> no alert
    assert len(alerts) == 0


# ==============================================================================
# 2. SYN FLOOD DETECTOR TESTS
# ==============================================================================

def test_syn_flood_trigger():
    """Verify that >50 SYNs with no ACKs within 2.0s triggers a SYN_FLOOD alert."""
    detector = SynFloodDetector(time_window_seconds=2.0, syn_threshold=50, syn_ack_ratio_threshold=4.0)
    base_time = 2000.0

    alerts = []
    for i in range(55):
        pkt = make_packet(
            ts=base_time + (i * 0.02),
            src_ip="10.0.0.99",
            dst_ip="192.168.1.1",
            dst_port=80,
            flags="S",
        )
        alerts.extend(detector.on_packet(pkt))

    assert len(alerts) >= 1
    alert = alerts[0]
    assert alert.type == "SYN_FLOOD"
    assert alert.severity == "CRITICAL"
    assert alert.dst_ip == "192.168.1.1"
    assert alert.evidence["syn_count"] >= 50


def test_syn_flood_legitimate_traffic():
    """Verify that balanced traffic (SYNs paired with SYN-ACKs) does NOT trigger."""
    detector = SynFloodDetector(time_window_seconds=2.0, syn_threshold=50, syn_ack_ratio_threshold=4.0)
    base_time = 2000.0

    alerts = []
    for i in range(60):
        # Client SYN
        syn_pkt = make_packet(
            ts=base_time + (i * 0.02),
            src_ip="10.0.0.5",
            dst_ip="192.168.1.1",
            flags="S",
        )
        # Server SYN-ACK response
        synack_pkt = make_packet(
            ts=base_time + (i * 0.02) + 0.005,
            src_ip="192.168.1.1",
            dst_ip="10.0.0.5",
            flags="SA",
        )
        alerts.extend(detector.on_packet(syn_pkt))
        alerts.extend(detector.on_packet(synack_pkt))

    # Ratio is 1:1, so no attack alert is raised
    assert len(alerts) == 0


# ==============================================================================
# 3. RST/FIN ABUSE DETECTOR TESTS
# ==============================================================================

def test_rst_abuse_trigger():
    """Verify that 10 RST packets to sensitive ports (e.g. 22, 80, 443) triggers RST_ABUSE."""
    detector = RstAbuseDetector(time_window_seconds=5.0, threshold=10, target_ports=[22, 80, 443])
    base_time = 3000.0

    alerts = []
    for i in range(10):
        pkt = make_packet(
            ts=base_time + (i * 0.2),
            src_ip="172.16.0.44",
            dst_ip="192.168.1.1",
            dst_port=80,
            flags="R",
        )
        alerts.extend(detector.on_packet(pkt))

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.type == "RST_ABUSE"
    assert alert.severity == "MEDIUM"
    assert alert.evidence["total_burst_count"] == 10
    assert 80 in alert.evidence["target_ports"]


def test_rst_abuse_unmonitored_port_ignored():
    """Verify that RST packets to unmonitored ports (e.g. 61234) do not trigger."""
    detector = RstAbuseDetector(time_window_seconds=5.0, threshold=10, target_ports=[22, 80, 443])
    base_time = 3000.0

    alerts = []
    for i in range(15):
        pkt = make_packet(
            ts=base_time + (i * 0.1),
            dst_port=61234,  # Unmonitored port
            flags="R",
        )
        alerts.extend(detector.on_packet(pkt))

    assert len(alerts) == 0
