"""
NetGuard Main Application Entry Point.

Wires capture/simulation threads, packet parser worker, detection engine,
TCP flow tracker, PCAP recorder, metrics aggregator, and the Flask-SocketIO dashboard.
"""
import argparse
import logging
from pathlib import Path
import queue
import random
import signal
import sys
import threading
import time

# Ensure project root is on sys.path when executed directly
project_root = str(Path(__file__).resolve().parent.parent)
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from netguard.alerts.manager import AlertManager
from netguard.alerts.notifier import EmailNotifier
from netguard.capture.pcap_recorder import PacketRecorder
from netguard.capture.sniffer import PacketCaptureEngine
from netguard.config import load_config
from netguard.detection.engine import DetectionEngine
from netguard.detection.flow_tracker import TCPFlowTracker
from netguard.metrics.aggregator import MetricsAggregator
from netguard.models import PacketEvent
from netguard.parsing.packet_parser import ParserWorker
from netguard.simulation import TrafficSimulator
from netguard.web.app import create_app
from netguard.web.events import WebSocketBroadcaster

# Configure clean logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s]: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("netguard.main")


def main():
    parser = argparse.ArgumentParser(
        description="NetGuard: Real-Time Network Intrusion Detection System"
    )
    parser.add_argument(
        "--mode",
        choices=["live", "simulation", "hybrid"],
        default="hybrid",
        help="Capture mode: 'live' (NIC sniffing), 'simulation' (synthetic traffic generator), or 'hybrid' (both)",
    )
    parser.add_argument(
        "-i", "--interface",
        type=str,
        default=None,
        help="Network interface to sniff on (e.g. en0, lo0). Defaults to config.yaml setting",
    )
    parser.add_argument(
        "-p", "--port",
        type=int,
        default=5050,
        help="Web dashboard HTTP port (default: 5050)",
    )
    parser.add_argument(
        "--host",
        type=str,
        default="127.0.0.1",
        help="Web dashboard bind host (default: 127.0.0.1)",
    )
    parser.add_argument(
        "-c", "--config",
        type=str,
        default="config.yaml",
        help="Path to YAML configuration file",
    )

    args = parser.parse_args()

    # 1. Load Configuration
    config = load_config(args.config)
    if args.interface:
        config.capture.interface = args.interface
    if args.port:
        config.web.port = args.port
    if args.host:
        config.web.host = args.host

    logger.info("----------------------------------------------------------")
    logger.info("NetGuard - Network Intrusion Detection System")
    logger.info("Mode: %s | Web Dashboard: http://%s:%d", args.mode.upper(), config.web.host, config.web.port)
    logger.info("----------------------------------------------------------")

    # 2. Concurrency Primitives
    packet_queue = queue.Queue(maxsize=config.capture.queue_maxsize)
    packet_recorder = PacketRecorder(maxlen=1000)
    flow_tracker = TCPFlowTracker(max_flows=500)

    # 3. Initialize Metrics Aggregator, Alert Manager & Email Notifier
    metrics_aggregator = MetricsAggregator(history_len=60)
    alert_manager = AlertManager(config=config.alerts)
    email_notifier = EmailNotifier()

    # 4. Initialize Detection Engine
    detection_engine = DetectionEngine(
        config=config.detection,
        on_alert=alert_manager.handle_alert,
    )

    # Reference for websocket broadcaster (set up after app creation)
    broadcaster_ref = [None]

    # 5. Core Packet Dispatch Pipeline
    def on_packet_event(event: PacketEvent):
        metrics_aggregator.on_packet(event)
        detection_engine.process_packet(event)
        flow_tracker.on_packet(event)
        packet_recorder.record_event(event)
        if broadcaster_ref[0]:
            broadcaster_ref[0].on_packet_event(event)

    # 6. Parser Worker Thread
    parser_worker = ParserWorker(packet_queue, on_packet_event=on_packet_event)
    parser_worker.start()

    # 7. Traffic & Attack Simulator Setup
    simulator = TrafficSimulator(on_packet_callback=on_packet_event)

    def trigger_attack(attack_type: str) -> dict:
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
        else:
            raise ValueError(f"Unknown attack type: {attack_type}")

    # Background baseline traffic generator
    sim_stop_event = threading.Event()

    def background_traffic_generator():
        while not sim_stop_event.is_set():
            pkt = simulator.generate_normal_packet()
            on_packet_event(pkt)
            time.sleep(random.uniform(0.08, 0.30))

    if args.mode in ("simulation", "hybrid"):
        bg_thread = threading.Thread(
            target=background_traffic_generator,
            name="NetGuard-SimTraffic",
            daemon=True,
        )
        bg_thread.start()

    # 8. Live Capture Engine
    capture_engine = None
    if args.mode in ("live", "hybrid"):
        try:
            capture_engine = PacketCaptureEngine(
                packet_queue=packet_queue,
                interface=config.capture.interface,
                bpf_filter=config.capture.bpf_filter,
                packet_recorder=packet_recorder,
            )
            metrics_aggregator.queue_size_supplier = lambda: packet_queue.qsize()
            metrics_aggregator.drop_count_supplier = lambda: capture_engine.dropped_packets
            capture_engine.start()
        except PermissionError:
            logger.warning("Root/sudo required for raw socket access. Falling back to simulation mode.")
            if args.mode == "live":
                bg_thread = threading.Thread(
                    target=background_traffic_generator,
                    name="NetGuard-SimTraffic",
                    daemon=True,
                )
                bg_thread.start()
        except Exception as e:
            logger.warning("Could not start live capture on '%s': %s", config.capture.interface, e)
            logger.warning("Running in simulation mode.")

    def health_provider() -> dict:
        cap_stats = capture_engine.get_stats() if capture_engine else {
            "is_running": False,
            "interface": "simulation",
            "total_captured": 0,
            "dropped_packets": 0,
            "current_queue_size": packet_queue.qsize(),
        }
        return cap_stats

    # 9. Create Flask-SocketIO Web App
    app, socketio = create_app(
        config=config,
        alert_manager=alert_manager,
        metrics_aggregator=metrics_aggregator,
        attack_simulator_callback=trigger_attack,
        health_provider=health_provider,
        flow_tracker=flow_tracker,
        packet_recorder=packet_recorder,
        detection_engine=detection_engine,
        packet_buffer_supplier=lambda: broadcaster_ref[0].get_packet_history() if broadcaster_ref[0] else [],
        email_notifier=email_notifier,
    )

    # 10. Start WebSocket Broadcaster
    broadcaster = WebSocketBroadcaster(
        socketio=socketio,
        metrics_aggregator=metrics_aggregator,
        alert_manager=alert_manager,
        interval_seconds=config.web.metrics_push_interval,
        email_notifier=email_notifier,
    )
    broadcaster_ref[0] = broadcaster
    broadcaster.start()

    # 11. Graceful Shutdown Signals
    def shutdown_handler(signum, frame):
        logger.info("\nReceived shutdown signal (%d). Stopping NetGuard gracefully...", signum)
        sim_stop_event.set()
        if capture_engine:
            capture_engine.stop()
        broadcaster.stop()
        parser_worker.stop()
        logger.info("NetGuard stopped cleanly. Goodbye!")
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown_handler)
    signal.signal(signal.SIGTERM, shutdown_handler)

    # 12. Run Web Server
    logger.info("Serving NetGuard Dashboard on http://%s:%d", config.web.host, config.web.port)
    socketio.run(app, host=config.web.host, port=config.web.port, debug=False, use_reloader=False, allow_unsafe_werkzeug=True)


if __name__ == "__main__":
    main()
