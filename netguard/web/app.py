"""
Flask application and REST API endpoints for NetGuard.
"""
import io
import logging
import os
import time
from typing import Optional
from flask import Flask, jsonify, render_template, request, Response, send_file
from flask_socketio import SocketIO

from netguard.alerts.manager import AlertManager
from netguard.alerts.notifier import EmailNotifier
from netguard.capture.pcap_recorder import export_alerts_csv
from netguard.config import AppConfig
from netguard.geo.lookup import lookup_alert_ips
from netguard.metrics.aggregator import MetricsAggregator
from netguard.reports.pdf_report import generate_pdf_report

logger = logging.getLogger("netguard.web")


def create_app(
    config: AppConfig,
    alert_manager: AlertManager,
    metrics_aggregator: MetricsAggregator,
    attack_simulator_callback=None,
    health_provider=None,
    flow_tracker=None,
    packet_recorder=None,
    detection_engine=None,
    packet_buffer_supplier=None,
    email_notifier: Optional[EmailNotifier] = None,
    device_tracker=None,
    rate_controller=None,
) -> tuple[Flask, SocketIO]:
    """
    Creates and configures the Flask application and Flask-SocketIO instance.
    Uses async_mode='threading' to avoid monkey-patching conflicts with Scapy.
    """
    template_dir = os.path.join(os.path.dirname(__file__), "templates")
    static_dir = os.path.join(os.path.dirname(__file__), "static")

    app = Flask(__name__, template_folder=template_dir, static_folder=static_dir)
    app.config["SECRET_KEY"] = "netguard-capstone-secret-2026"

    socketio = SocketIO(app, async_mode="threading", cors_allowed_origins="*")

    start_time = time.time()

    # --------------------------------------------------------------------------
    # Web UI Routes
    # --------------------------------------------------------------------------
    @app.route("/")
    def index():
        return render_template("index.html")

    # --------------------------------------------------------------------------
    # REST API Endpoints
    # --------------------------------------------------------------------------
    @app.route("/api/devices", methods=["GET"])
    def get_devices():
        """Returns inventory of all communicating hosts."""
        limit = int(request.args.get("limit", 50))
        devices = device_tracker.get_devices(limit=limit) if device_tracker else []
        return jsonify({"count": len(devices), "devices": devices})

    @app.route("/api/firewall/rule", methods=["POST"])
    def generate_firewall_rule():
        """Generates OS-specific firewall block commands."""
        data = request.get_json() or {}
        ip = data.get("ip", "").strip()
        if not ip:
            return jsonify({"error": "IP address required"}), 400
        return jsonify({
            "ip": ip,
            "linux": f"sudo iptables -A INPUT -s {ip} -j DROP",
            "windows": f'netsh advfirewall firewall add rule name="NetGuard_Block_{ip}" dir=in action=block remoteip={ip}',
            "macos": f"sudo pfctl -t blocklist -T add {ip}",
        })

    @app.route("/api/health", methods=["GET"])
    def health():
        uptime = round(time.time() - start_time, 1)
        extra_health = health_provider() if health_provider else {}
        active_flows = flow_tracker.get_active_count() if flow_tracker else 0
        pcap_count = packet_recorder.get_count() if packet_recorder else 0
        return jsonify({
            "status": "healthy",
            "uptime_seconds": uptime,
            "active_flows": active_flows,
            "recorded_packets": pcap_count,
            **extra_health,
        })

    @app.route("/api/alerts", methods=["GET"])
    def get_alerts():
        limit = int(request.args.get("limit", 100))
        severity = request.args.get("severity")
        alerts = alert_manager.get_alerts(limit=limit, severity=severity)
        return jsonify({"count": len(alerts), "alerts": alerts})

    @app.route("/api/alerts", methods=["DELETE"])
    def clear_alerts():
        alert_manager.clear_alerts()
        return jsonify({"status": "cleared", "message": "All alerts purged."})

    @app.route("/api/connections", methods=["GET"])
    def get_connections():
        """Returns live TCP connections and handshake states."""
        flows = flow_tracker.get_flows(limit=100) if flow_tracker else []
        return jsonify({"count": len(flows), "flows": flows})

    @app.route("/api/packets", methods=["GET"])
    def get_packets():
        """Returns recent packet history for live dissector."""
        packets = packet_buffer_supplier() if packet_buffer_supplier else []
        return jsonify({"count": len(packets), "packets": packets})

    @app.route("/api/metrics/history", methods=["GET"])
    def get_metrics_history():
        history = metrics_aggregator.get_history()
        return jsonify({"count": len(history), "history": history})

    @app.route("/api/metrics/reset", methods=["POST"])
    def reset_metrics():
        """Resets cumulative packet and volume counters for a fresh demo run."""
        metrics_aggregator.reset_counters()
        return jsonify({"status": "reset", "message": "Session metrics reset successfully."})

    @app.route("/api/config", methods=["GET"])
    def get_configuration():
        det = config.detection
        live_rules = detection_engine.get_config_dict() if detection_engine else {}
        return jsonify({
            "capture": {
                "interface": config.capture.interface,
                "filter": config.capture.bpf_filter,
            },
            "rules": live_rules or {
                "port_scan": {
                    "enabled": det.port_scan.enabled,
                    "window_s": det.port_scan.time_window_seconds,
                    "threshold_ports": det.port_scan.unique_port_threshold,
                    "severity": det.port_scan.severity,
                },
                "syn_flood": {
                    "enabled": det.syn_flood.enabled,
                    "window_s": det.syn_flood.time_window_seconds,
                    "threshold_syn": det.syn_flood.syn_threshold,
                    "ratio": det.syn_flood.syn_ack_ratio_threshold,
                    "severity": det.syn_flood.severity,
                },
                "rst_abuse": {
                    "enabled": det.rst_abuse.enabled,
                    "window_s": det.rst_abuse.time_window_seconds,
                    "threshold_packets": det.rst_abuse.threshold,
                    "monitored_ports": det.rst_abuse.target_ports,
                    "severity": det.rst_abuse.severity,
                },
            },
            "alerts": {
                "cooldown_s": config.alerts.cooldown_seconds,
                "whitelist": config.alerts.whitelist_ips,
            },
        })

    @app.route("/api/config", methods=["POST"])
    def update_configuration():
        """Updates live detector thresholds without restart."""
        updates = request.get_json() or {}
        if detection_engine:
            updated = detection_engine.update_thresholds(updates)
            return jsonify({"status": "updated", "rules": updated})
        return jsonify({"error": "Engine not attached"}), 400

    @app.route("/api/export/pcap", methods=["GET"])
    def export_pcap():
        """Exports captured packets as a standard Wireshark PCAP file."""
        if not packet_recorder:
            return jsonify({"error": "Recorder not available"}), 400

        pcap_data = packet_recorder.export_pcap_bytes()
        return Response(
            pcap_data,
            mimetype="application/vnd.tcpdump.pcap",
            headers={
                "Content-Disposition": "attachment; filename=netguard_traffic.pcap",
                "Content-Length": str(len(pcap_data)),
            },
        )

    @app.route("/api/export/pcap/alert/<alert_id>", methods=["GET"])
    def export_alert_pcap(alert_id):
        """Exports specifically the packets that triggered a given security alert."""
        if not packet_recorder:
            return jsonify({"error": "Recorder not available"}), 400

        pcap_data = packet_recorder.export_incident_pcap_bytes(alert_id)
        return Response(
            pcap_data,
            mimetype="application/vnd.tcpdump.pcap",
            headers={
                "Content-Disposition": f"attachment; filename=incident_{alert_id[:8]}.pcap",
                "Content-Length": str(len(pcap_data)),
            },
        )

    @app.route("/api/simulate/rate", methods=["POST"])
    def set_simulation_rate():
        """Dynamically adjusts synthetic traffic rate multiplier."""
        data = request.get_json() or {}
        rate = float(data.get("rate", 1.0))
        if rate_controller:
            rate_controller(rate)
            return jsonify({"status": "updated", "rate": rate})
        return jsonify({"status": "noop", "rate": rate})

    @app.route("/api/export/alerts/csv", methods=["GET"])
    def export_alerts():
        """Exports detected alerts as a CSV report."""
        alerts = alert_manager.get_alerts(limit=500)
        csv_str = export_alerts_csv(alerts)
        return Response(
            csv_str,
            mimetype="text/csv",
            headers={"Content-Disposition": "attachment; filename=netguard_alerts.csv"},
        )

    @app.route("/api/simulate", methods=["POST"])
    def trigger_simulation():
        """Allows triggering test attacks right from the web dashboard."""
        if not attack_simulator_callback:
            return jsonify({"error": "Simulator not enabled in this mode"}), 400

        data = request.get_json() or {}
        attack_type = data.get("type", "port_scan").lower()

        try:
            result = attack_simulator_callback(attack_type)
            return jsonify({
                "status": "success",
                "attack": attack_type,
                "details": result,
            })
        except Exception as e:
            logger.error("Simulation error: %s", e)
            return jsonify({"error": str(e)}), 500

    # --------------------------------------------------------------------------
    # IP Blacklist Management
    # --------------------------------------------------------------------------
    @app.route("/api/blacklist", methods=["GET"])
    def get_blacklist():
        entries = alert_manager.get_blacklist()
        return jsonify({"count": len(entries), "blacklist": entries})

    @app.route("/api/blacklist", methods=["POST"])
    def add_blacklist():
        data = request.get_json() or {}
        ip = data.get("ip", "").strip()
        reason = data.get("reason", "Manually blocked")
        if not ip:
            return jsonify({"error": "IP address required"}), 400
        added = alert_manager.add_to_blacklist(ip, reason)
        return jsonify({"status": "added" if added else "already_exists", "ip": ip})

    @app.route("/api/blacklist", methods=["DELETE"])
    def remove_blacklist():
        data = request.get_json() or {}
        ip = data.get("ip", "").strip()
        if not ip:
            return jsonify({"error": "IP address required"}), 400
        removed = alert_manager.remove_from_blacklist(ip)
        return jsonify({"status": "removed" if removed else "not_found", "ip": ip})

    # --------------------------------------------------------------------------
    # Alert Statistics
    # --------------------------------------------------------------------------
    @app.route("/api/alerts/stats", methods=["GET"])
    def get_alert_stats():
        return jsonify(alert_manager.get_alert_stats())

    # --------------------------------------------------------------------------
    # IP Geolocation Data
    # --------------------------------------------------------------------------
    @app.route("/api/geo/attackers", methods=["GET"])
    def get_geo_attackers():
        alerts = alert_manager.get_alerts(limit=500)
        geo_data = lookup_alert_ips(alerts)
        return jsonify({"count": len(geo_data), "locations": geo_data})

    # --------------------------------------------------------------------------
    # PDF Report Export
    # --------------------------------------------------------------------------
    @app.route("/api/export/report/pdf", methods=["GET"])
    def export_pdf_report():
        alerts = alert_manager.get_alerts(limit=500)
        stats = alert_manager.get_alert_stats()
        uptime = round(time.time() - start_time, 1)
        hrs = int(uptime // 3600)
        mins = int((uptime % 3600) // 60)
        secs = int(uptime % 60)
        metrics_summary = {
            "total_packets": metrics_aggregator.total_packets,
            "total_bytes_str": f"{metrics_aggregator.total_bytes / 1024:.1f} KB",
            "uptime": f"{hrs}h {mins}m {secs}s",
        }
        pdf_bytes = generate_pdf_report(alerts, stats, metrics_summary)
        return Response(
            pdf_bytes,
            mimetype="application/pdf",
            headers={
                "Content-Disposition": "attachment; filename=netguard_report.pdf",
                "Content-Length": str(len(pdf_bytes)),
            },
        )

    # --------------------------------------------------------------------------
    # Email Notification Settings
    # --------------------------------------------------------------------------
    @app.route("/api/settings/email", methods=["GET"])
    def get_email_settings():
        if not email_notifier:
            return jsonify({"enabled": False, "message": "Email notifier not configured"})
        return jsonify(email_notifier.get_settings())

    @app.route("/api/settings/email", methods=["POST"])
    def update_email_settings():
        if not email_notifier:
            return jsonify({"error": "Email notifier not available"}), 400
        data = request.get_json() or {}
        email_notifier.update_settings(
            enabled=data.get("enabled"),
            recipient=data.get("recipient_email"),
            smtp_host=data.get("smtp_host"),
            smtp_port=data.get("smtp_port"),
            sender_email=data.get("sender_email"),
            sender_password=data.get("sender_password"),
            min_severity=data.get("min_severity"),
        )
        return jsonify({"status": "updated", "settings": email_notifier.get_settings()})

    return app, socketio
