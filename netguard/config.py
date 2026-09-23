"""Configuration loader and schema validator for NetGuard."""
import os
from dataclasses import dataclass, field
from typing import List
import yaml


@dataclass
class PortScanConfig:
    enabled: bool = True
    time_window_seconds: float = 3.0
    unique_port_threshold: int = 15
    severity: str = "HIGH"


@dataclass
class SynFloodConfig:
    enabled: bool = True
    time_window_seconds: float = 2.0
    syn_threshold: int = 50
    syn_ack_ratio_threshold: float = 4.0
    half_open_timeout: float = 5.0
    severity: str = "CRITICAL"


@dataclass
class RstAbuseConfig:
    enabled: bool = True
    time_window_seconds: float = 5.0
    threshold: int = 10
    target_ports: List[int] = field(default_factory=lambda: [22, 80, 443, 3389, 8080])
    severity: str = "MEDIUM"


@dataclass
class DetectionConfig:
    port_scan: PortScanConfig = field(default_factory=PortScanConfig)
    syn_flood: SynFloodConfig = field(default_factory=SynFloodConfig)
    rst_abuse: RstAbuseConfig = field(default_factory=RstAbuseConfig)


@dataclass
class CaptureConfig:
    interface: str = "auto"
    bpf_filter: str = "ip or ip6"
    queue_maxsize: int = 10000


@dataclass
class AlertsConfig:
    cooldown_seconds: float = 10.0
    whitelist_ips: List[str] = field(default_factory=lambda: ["127.0.0.1", "::1"])
    db_path: str = "netguard.db"
    max_tracked_sources: int = 10000


@dataclass
class WebConfig:
    host: str = "127.0.0.1"
    port: int = 5050
    metrics_push_interval: float = 1.0


@dataclass
class AppConfig:
    capture: CaptureConfig = field(default_factory=CaptureConfig)
    detection: DetectionConfig = field(default_factory=DetectionConfig)
    alerts: AlertsConfig = field(default_factory=AlertsConfig)
    web: WebConfig = field(default_factory=WebConfig)


def load_config(config_path: str = "config.yaml") -> AppConfig:
    """Load configuration from a YAML file, falling back to defaults if not found."""
    if not os.path.exists(config_path):
        return AppConfig()

    with open(config_path, "r") as f:
        data = yaml.safe_load(f) or {}

    cap_data = data.get("capture", {})
    capture_cfg = CaptureConfig(
        interface=cap_data.get("interface", "auto"),
        bpf_filter=cap_data.get("bpf_filter", "ip or ip6"),
        queue_maxsize=cap_data.get("queue_maxsize", 10000),
    )

    det_data = data.get("detection", {})
    ps_data = det_data.get("port_scan", {})
    port_scan_cfg = PortScanConfig(
        enabled=ps_data.get("enabled", True),
        time_window_seconds=float(ps_data.get("time_window_seconds", 3.0)),
        unique_port_threshold=int(ps_data.get("unique_port_threshold", 15)),
        severity=ps_data.get("severity", "HIGH"),
    )

    sf_data = det_data.get("syn_flood", {})
    syn_flood_cfg = SynFloodConfig(
        enabled=sf_data.get("enabled", True),
        time_window_seconds=float(sf_data.get("time_window_seconds", 2.0)),
        syn_threshold=int(sf_data.get("syn_threshold", 50)),
        syn_ack_ratio_threshold=float(sf_data.get("syn_ack_ratio_threshold", 4.0)),
        half_open_timeout=float(sf_data.get("half_open_timeout", 5.0)),
        severity=sf_data.get("severity", "CRITICAL"),
    )

    ra_data = det_data.get("rst_abuse", {})
    rst_abuse_cfg = RstAbuseConfig(
        enabled=ra_data.get("enabled", True),
        time_window_seconds=float(ra_data.get("time_window_seconds", 5.0)),
        threshold=int(ra_data.get("threshold", 10)),
        target_ports=list(ra_data.get("target_ports", [22, 80, 443, 3389, 8080])),
        severity=ra_data.get("severity", "MEDIUM"),
    )

    det_cfg = DetectionConfig(
        port_scan=port_scan_cfg,
        syn_flood=syn_flood_cfg,
        rst_abuse=rst_abuse_cfg,
    )

    al_data = data.get("alerts", {})
    alerts_cfg = AlertsConfig(
        cooldown_seconds=float(al_data.get("cooldown_seconds", 10.0)),
        whitelist_ips=list(al_data.get("whitelist_ips", ["127.0.0.1", "::1"])),
        db_path=al_data.get("db_path", "netguard.db"),
        max_tracked_sources=int(al_data.get("max_tracked_sources", 10000)),
    )

    wb_data = data.get("web", {})
    web_cfg = WebConfig(
        host=wb_data.get("host", "127.0.0.1"),
        port=int(wb_data.get("port", 5000)),
        metrics_push_interval=float(wb_data.get("metrics_push_interval", 1.0)),
    )

    return AppConfig(
        capture=capture_cfg,
        detection=det_cfg,
        alerts=alerts_cfg,
        web=web_cfg,
    )
