"""
WebSocket event emitter and background 1 Hz metrics publisher using Flask-SocketIO.
"""
from collections import deque
import logging
import threading
import time
from typing import Optional
from flask_socketio import SocketIO

from netguard.alerts.manager import AlertManager
from netguard.alerts.notifier import EmailNotifier
from netguard.metrics.aggregator import MetricsAggregator
from netguard.models import Alert, MetricSnapshot, PacketEvent

logger = logging.getLogger("netguard.events")


class WebSocketBroadcaster:
    """
    Manages real-time WebSocket pushes to connected web dashboard clients.
    Pushes:
    - 1 Hz 'metrics' events containing bandwidth, pps, protocol counts, top talkers.
    - Instant 'alert' events when a detector triggers an intrusion alert.
    - Streamed 'packet' events for the live Wireshark-style packet inspector.
    """

    def __init__(
        self,
        socketio: SocketIO,
        metrics_aggregator: MetricsAggregator,
        alert_manager: AlertManager,
        interval_seconds: float = 1.0,
        email_notifier: Optional[EmailNotifier] = None,
    ):
        self.socketio = socketio
        self.metrics_aggregator = metrics_aggregator
        self.alert_manager = alert_manager
        self.interval = interval_seconds
        self.email_notifier = email_notifier
        self._running = False
        self._thread: Optional[threading.Thread] = None

        # Rolling packet buffer for live dissector (last 100 packets)
        self.packet_history = deque(maxlen=100)
        self._last_packet_emit = 0.0
        self._lock = threading.Lock()

        # Register alert callback in AlertManager
        self.alert_manager.on_alert_dispatched = self.on_alert_triggered

        # Setup connection handlers
        self._setup_socket_handlers()

    def _setup_socket_handlers(self):
        @self.socketio.on("connect")
        def handle_connect():
            logger.debug("Dashboard client connected to WebSocket.")
            history = self.metrics_aggregator.get_history()
            latest = history[-1] if history else None
            if latest:
                self.socketio.emit("metrics", latest)

        @self.socketio.on("disconnect")
        def handle_disconnect():
            logger.debug("Dashboard client disconnected from WebSocket.")

    def on_alert_triggered(self, alert: Alert):
        """Called when an alert is accepted and persists to SQLite."""
        try:
            self.socketio.emit("alert", alert.to_dict())
        except Exception as e:
            logger.error("Failed to emit alert via SocketIO: %s", e)
        if self.email_notifier:
            self.email_notifier.send_alert_email(alert)

    def on_packet_event(self, event: PacketEvent):
        """Streams packet to live dissector table (throttled to avoid UI lockup)."""
        now = time.time()
        d = event.to_dict()
        with self._lock:
            self.packet_history.append(d)
            # Throttle emission to ~12 packets per second max
            if now - self._last_packet_emit >= 0.08:
                self._last_packet_emit = now
                try:
                    self.socketio.emit("packet", d)
                except Exception:
                    pass

    def get_packet_history(self) -> list:
        with self._lock:
            return list(self.packet_history)

    def _metrics_loop(self):
        logger.info("1 Hz Metrics broadcast loop started.")
        while self._running:
            start_t = time.time()
            try:
                snapshot = self.metrics_aggregator.tick(now=start_t)
                self.socketio.emit("metrics", snapshot.to_dict())
            except Exception as e:
                logger.error("Error in metrics broadcast loop: %s", e)

            elapsed = time.time() - start_t
            sleep_time = max(0.05, self.interval - elapsed)
            time.sleep(sleep_time)

        logger.info("Metrics broadcast loop stopped.")

    def start(self):
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(
            target=self._metrics_loop,
            name="NetGuard-MetricsBroadcaster",
            daemon=True,
        )
        self._thread.start()

    def stop(self):
        self._running = False
