"""
End-to-end integration test verifying Flask REST APIs, attack simulations,
PCAP exports, flow tracking, and dynamic configuration updates.
"""
import os
import tempfile
import pytest

from netguard.alerts.manager import AlertManager
from netguard.capture.pcap_recorder import PacketRecorder
from netguard.config import AppConfig
from netguard.detection.engine import DetectionEngine
from netguard.detection.flow_tracker import TCPFlowTracker
from netguard.metrics.aggregator import MetricsAggregator
from netguard.models import PacketEvent
from netguard.simulation import TrafficSimulator
from netguard.web.app import create_app


@pytest.fixture
def test_client():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        db_path = tmp.name

    config = AppConfig()
    config.alerts.db_path = db_path
    config.alerts.cooldown_seconds = 0.1

    packet_recorder = PacketRecorder(maxlen=100)
    flow_tracker = TCPFlowTracker(max_flows=100)
    metrics_aggregator = MetricsAggregator(history_len=60)
    alert_manager = AlertManager(config=config.alerts)
    detection_engine = DetectionEngine(
        config=config.detection,
        on_alert=alert_manager.handle_alert,
    )

    def on_packet(event: PacketEvent):
        metrics_aggregator.on_packet(event)
        detection_engine.process_packet(event)
        flow_tracker.on_packet(event)
        packet_recorder.record_event(event)

    simulator = TrafficSimulator(on_packet_callback=on_packet)

    def trigger_attack(attack_type: str):
        t = attack_type.lower()
        if t in ("port_scan", "vertical_port_scan"):
            return simulator.simulate_vertical_port_scan()
        elif t in ("port_scan_horizontal", "horizontal_port_scan"):
            return simulator.simulate_horizontal_port_scan()
        elif t in ("syn_flood", "synflood"):
            return simulator.simulate_syn_flood()
        elif t in ("rst_abuse", "rst_fin_abuse"):
            return simulator.simulate_rst_abuse()
        elif t in ("icmp_flood", "ping_flood"):
            return simulator.simulate_icmp_flood()
        raise ValueError(f"Unknown attack {attack_type}")

    app, _ = create_app(
        config=config,
        alert_manager=alert_manager,
        metrics_aggregator=metrics_aggregator,
        attack_simulator_callback=trigger_attack,
        health_provider=lambda: {"interface": "test", "total_captured": 100},
        flow_tracker=flow_tracker,
        packet_recorder=packet_recorder,
        detection_engine=detection_engine,
        packet_buffer_supplier=lambda: [],
    )
    app.config["TESTING"] = True

    with app.test_client() as client:
        yield client

    if os.path.exists(db_path):
        try:
            os.remove(db_path)
        except (PermissionError, OSError):
            pass


def test_health_endpoint(test_client):
    res = test_client.get("/api/health")
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "healthy"
    assert data["interface"] == "test"


def test_config_endpoints(test_client):
    # GET
    res = test_client.get("/api/config")
    assert res.status_code == 200
    data = res.get_json()
    assert "rules" in data

    # POST (dynamic update)
    update_res = test_client.post("/api/config", json={
        "port_scan_threshold": 10,
        "syn_ratio": 3.5,
    })
    assert update_res.status_code == 200
    updated_data = update_res.get_json()
    assert updated_data["rules"]["port_scan"]["threshold"] == 10
    assert updated_data["rules"]["syn_flood"]["ratio"] == 3.5


def test_simulate_port_scan_and_fetch_alerts(test_client):
    sim_res = test_client.post("/api/simulate", json={"type": "port_scan"})
    assert sim_res.status_code == 200

    alerts_res = test_client.get("/api/alerts")
    assert alerts_res.status_code == 200
    data = alerts_res.get_json()
    assert data["count"] >= 1
    types = [a["type"] for a in data["alerts"]]
    assert "PORT_SCAN" in types


def test_simulate_syn_flood(test_client):
    sim_res = test_client.post("/api/simulate", json={"type": "syn_flood"})
    assert sim_res.status_code == 200

    alerts_res = test_client.get("/api/alerts?severity=CRITICAL")
    assert alerts_res.status_code == 200
    data = alerts_res.get_json()
    assert data["count"] >= 1
    assert data["alerts"][0]["type"] == "SYN_FLOOD"


def test_connections_endpoint(test_client):
    # Trigger an attack to generate TCP traffic
    test_client.post("/api/simulate", json={"type": "syn_flood"})
    res = test_client.get("/api/connections")
    assert res.status_code == 200
    data = res.get_json()
    assert "flows" in data
    assert len(data["flows"]) >= 1


def test_export_pcap_endpoint(test_client):
    # Generate some traffic first
    test_client.post("/api/simulate", json={"type": "port_scan"})
    res = test_client.get("/api/export/pcap")
    assert res.status_code == 200
    assert res.mimetype == "application/vnd.tcpdump.pcap"
    assert len(res.data) > 24  # Standard PCAP global header is 24 bytes


def test_export_alerts_csv_endpoint(test_client):
    test_client.post("/api/simulate", json={"type": "port_scan"})
    res = test_client.get("/api/export/alerts/csv")
    assert res.status_code == 200
    assert res.mimetype == "text/csv"
    assert b"Alert ID" in res.data
    assert b"PORT_SCAN" in res.data
