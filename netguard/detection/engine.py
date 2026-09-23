"""
Detection Engine for NetGuard.

Orchestrates multiple intrusion detection rules and processes incoming
PacketEvents through all active detectors.
"""
import logging
from typing import Callable, List, Optional

from netguard.config import DetectionConfig
from netguard.detection.base import BaseDetector
from netguard.detection.port_scan import PortScanDetector
from netguard.detection.rst_abuse import RstAbuseDetector
from netguard.detection.syn_flood import SynFloodDetector
from netguard.models import Alert, PacketEvent

logger = logging.getLogger("netguard.detection")


class DetectionEngine:
    """
    Main detection coordinator. Evaluates each packet against all active
    rule detectors and forwards generated alerts to an alert handler callback.
    """

    def __init__(
        self,
        config: Optional[DetectionConfig] = None,
        on_alert: Optional[Callable[[Alert], None]] = None,
    ):
        self.config = config or DetectionConfig()
        self.on_alert = on_alert
        self.detectors: List[BaseDetector] = []
        self._init_detectors()

    def _init_detectors(self):
        # 1. Port Scan Detector
        ps_cfg = self.config.port_scan
        self.port_scan_detector = PortScanDetector(
            time_window_seconds=ps_cfg.time_window_seconds,
            unique_port_threshold=ps_cfg.unique_port_threshold,
            severity=ps_cfg.severity,
            enabled=ps_cfg.enabled,
        )
        self.detectors.append(self.port_scan_detector)

        # 2. SYN Flood Detector
        sf_cfg = self.config.syn_flood
        self.syn_flood_detector = SynFloodDetector(
            time_window_seconds=sf_cfg.time_window_seconds,
            syn_threshold=sf_cfg.syn_threshold,
            syn_ack_ratio_threshold=sf_cfg.syn_ack_ratio_threshold,
            half_open_timeout=sf_cfg.half_open_timeout,
            severity=sf_cfg.severity,
            enabled=sf_cfg.enabled,
        )
        self.detectors.append(self.syn_flood_detector)

        # 3. RST/FIN Abuse Detector
        ra_cfg = self.config.rst_abuse
        self.rst_abuse_detector = RstAbuseDetector(
            time_window_seconds=ra_cfg.time_window_seconds,
            threshold=ra_cfg.threshold,
            target_ports=ra_cfg.target_ports,
            severity=ra_cfg.severity,
            enabled=ra_cfg.enabled,
        )
        self.detectors.append(self.rst_abuse_detector)

    def process_packet(self, event: PacketEvent, now: Optional[float] = None) -> List[Alert]:
        """Runs the packet event through all enabled detectors."""
        all_alerts: List[Alert] = []

        for detector in self.detectors:
            try:
                alerts = detector.on_packet(event, now=now)
                for alert in alerts:
                    all_alerts.append(alert)
                    if self.on_alert:
                        self.on_alert(alert)
            except Exception as e:
                logger.error("Error in detector %s: %s", detector.name, e)

        return all_alerts

    def reset_all(self):
        """Resets state across all detectors."""
        for detector in self.detectors:
            detector.reset()

    def update_thresholds(self, updates: dict) -> dict:
        """Dynamically tunes detector thresholds without restarting the server."""
        if "port_scan_threshold" in updates:
            self.port_scan_detector.port_threshold = int(updates["port_scan_threshold"])
        if "port_scan_window" in updates:
            self.port_scan_detector.time_window = float(updates["port_scan_window"])
        if "syn_threshold" in updates:
            self.syn_flood_detector.syn_threshold = int(updates["syn_threshold"])
        if "syn_ratio" in updates:
            self.syn_flood_detector.ratio_threshold = float(updates["syn_ratio"])
        if "rst_threshold" in updates:
            self.rst_abuse_detector.threshold = int(updates["rst_threshold"])
        if "rst_window" in updates:
            self.rst_abuse_detector.time_window = float(updates["rst_window"])
        return self.get_config_dict()

    def get_config_dict(self) -> dict:
        return {
            "port_scan": {
                "threshold": self.port_scan_detector.port_threshold,
                "window_s": self.port_scan_detector.time_window,
                "enabled": self.port_scan_detector.enabled,
            },
            "syn_flood": {
                "threshold": self.syn_flood_detector.syn_threshold,
                "ratio": self.syn_flood_detector.ratio_threshold,
                "window_s": self.syn_flood_detector.time_window,
                "enabled": self.syn_flood_detector.enabled,
            },
            "rst_abuse": {
                "threshold": self.rst_abuse_detector.threshold,
                "window_s": self.rst_abuse_detector.time_window,
                "target_ports": list(self.rst_abuse_detector.target_ports),
                "enabled": self.rst_abuse_detector.enabled,
            },
        }
