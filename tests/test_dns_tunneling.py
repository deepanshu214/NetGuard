"""
Tests for DnsTunnelingDetector.
"""
from netguard.detection.dns_tunneling import DnsTunnelingDetector
from netguard.models import PacketEvent


def test_dns_tunneling_trigger():
    detector = DnsTunnelingDetector(
        time_window_seconds=4.0,
        query_threshold=15,
        min_payload_len=90,
    )

    now = 100.0
    alerts = []
    for i in range(16):
        event = PacketEvent(
            ts=now + (i * 0.1),
            src_ip="192.168.1.150",
            dst_ip="8.8.8.8",
            ip_ver=4,
            proto="UDP",
            src_port=50000 + i,
            dst_port=53,
            length=180,
            info=f"DNS Query TXT: chunk{i}.secret.c2.attacker.com",
        )
        detected = detector.on_packet(event, now=event.ts)
        alerts.extend(detected)

    assert len(alerts) >= 1
    a = alerts[0]
    assert a.type == "DNS_TUNNELING"
    assert a.severity == "HIGH"
    assert a.src_ip == "192.168.1.150"
    assert a.dst_ip == "8.8.8.8"
    assert a.evidence["dns_queries_count"] >= 15


def test_dns_tunneling_ignores_normal_small_dns():
    detector = DnsTunnelingDetector(
        time_window_seconds=4.0,
        query_threshold=15,
        min_payload_len=90,
    )

    now = 100.0
    alerts = []
    for i in range(20):
        # Small standard A query (35 bytes, no "DNS" keyword in info)
        event = PacketEvent(
            ts=now + (i * 0.1),
            src_ip="192.168.1.50",
            dst_ip="1.1.1.1",
            ip_ver=4,
            proto="UDP",
            src_port=53000 + i,
            dst_port=53,
            length=35,
            info="",
        )
        detected = detector.on_packet(event, now=event.ts)
        alerts.extend(detected)

    assert len(alerts) == 0
