"""
Unit tests for NetGuard AlertManager and MetricsAggregator.
"""
import os
import tempfile
import pytest

from netguard.alerts.manager import AlertManager
from netguard.config import AlertsConfig
from netguard.metrics.aggregator import MetricsAggregator
from netguard.models import Alert, PacketEvent


def test_alert_manager_persistence_and_cooldown():
    """Verify alert persistence and cooldown deduplication in AlertManager."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        db_path = tmp.name

    try:
        config = AlertsConfig(
            cooldown_seconds=5.0,
            whitelist_ips=["127.0.0.1"],
            db_path=db_path,
        )
        dispatched_alerts = []
        manager = AlertManager(
            config=config,
            on_alert_dispatched=lambda a: dispatched_alerts.append(a),
        )

        alert1 = Alert(
            ts=100.0,
            type="PORT_SCAN",
            severity="HIGH",
            src_ip="192.168.1.50",
            dst_ip="192.168.1.1",
            summary="Port scan test 1",
            evidence={"ports": 15},
        )

        # 1. First alert should be accepted
        accepted1 = manager.handle_alert(alert1, now=100.0)
        assert accepted1 is True
        assert len(dispatched_alerts) == 1

        # 2. Duplicate alert from same source at t=102.0 (within 5s cooldown) should be suppressed
        alert2 = Alert(
            ts=102.0,
            type="PORT_SCAN",
            severity="HIGH",
            src_ip="192.168.1.50",
            dst_ip="192.168.1.1",
            summary="Port scan test 2",
        )
        accepted2 = manager.handle_alert(alert2, now=102.0)
        assert accepted2 is False
        assert len(dispatched_alerts) == 1

        # 3. Alert from whitelisted IP should be suppressed
        alert_wl = Alert(
            ts=103.0,
            type="PORT_SCAN",
            severity="HIGH",
            src_ip="127.0.0.1",
            dst_ip="127.0.0.1",
            summary="Whitelisted scan",
        )
        assert manager.handle_alert(alert_wl, now=103.0) is False

        # 4. Query from database
        stored = manager.get_alerts(limit=10)
        assert len(stored) == 1
        assert stored[0]["src_ip"] == "192.168.1.50"
        assert stored[0]["evidence"]["ports"] == 15

        # 5. Alert after cooldown expired (t=106.0 > 100.0 + 5.0) should be accepted
        alert3 = Alert(
            ts=106.0,
            type="PORT_SCAN",
            severity="HIGH",
            src_ip="192.168.1.50",
            dst_ip="192.168.1.1",
            summary="Port scan test 3",
        )
        assert manager.handle_alert(alert3, now=106.0) is True
        assert len(manager.get_alerts(limit=10)) == 2

    finally:
        if os.path.exists(db_path):
            try:
                os.remove(db_path)
            except (PermissionError, OSError):
                pass


def test_metrics_aggregator_snapshot_and_history():
    """Verify that MetricsAggregator computes rates, top talkers, and history."""
    aggregator = MetricsAggregator(history_len=10)

    # Feed 10 packets of 100 bytes each
    for i in range(10):
        pkt = PacketEvent(
            ts=1000.0,
            src_ip="192.168.1.200",
            dst_ip="192.168.1.1",
            ip_ver=4,
            proto="TCP",
            src_port=50000 + i,
            dst_port=80,
            length=100,
        )
        aggregator.on_packet(pkt)

    # Trigger 1-second tick
    snapshot = aggregator.tick(now=1001.0)

    assert snapshot.total_packets == 10
    assert snapshot.total_bytes == 1000
    assert snapshot.protocol_counts["TCP"] == 10
    assert len(snapshot.top_talkers) == 1
    assert snapshot.top_talkers[0]["ip"] == "192.168.1.200"
    assert snapshot.top_talkers[0]["bytes"] == 1000

    # History ring buffer
    history = aggregator.get_history()
    assert len(history) == 1
    assert history[0]["total_packets"] == 10
