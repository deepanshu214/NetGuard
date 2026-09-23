"""Email notification sender for critical NetGuard alerts."""
import logging
import smtplib
import threading
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Optional

from netguard.models import Alert

logger = logging.getLogger("netguard.notifier")


class EmailNotifier:
    """Sends email notifications for critical/high severity alerts."""

    def __init__(
        self,
        enabled: bool = False,
        smtp_host: str = "smtp.gmail.com",
        smtp_port: int = 587,
        sender_email: str = "",
        sender_password: str = "",
        recipient_email: str = "",
        min_severity: str = "HIGH",
    ):
        self.enabled = enabled
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.sender_email = sender_email
        self.sender_password = sender_password
        self.recipient_email = recipient_email
        self.min_severity = min_severity
        self._severity_order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

    def should_notify(self, alert: Alert) -> bool:
        if not self.enabled or not self.recipient_email:
            return False
        alert_level = self._severity_order.get(alert.severity, 0)
        min_level = self._severity_order.get(self.min_severity, 2)
        return alert_level >= min_level

    def send_alert_email(self, alert: Alert):
        """Sends an email notification for the given alert (runs in background thread)."""
        if not self.should_notify(alert):
            return
        thread = threading.Thread(
            target=self._send_email_sync,
            args=(alert,),
            daemon=True,
        )
        thread.start()

    def _send_email_sync(self, alert: Alert):
        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = f"[NetGuard {alert.severity}] {alert.type} from {alert.src_ip}"
            msg["From"] = self.sender_email
            msg["To"] = self.recipient_email

            body = (
                f"NetGuard Security Alert\n"
                f"{'=' * 40}\n\n"
                f"Type:     {alert.type}\n"
                f"Severity: {alert.severity}\n"
                f"Source:   {alert.src_ip}\n"
                f"Target:   {alert.dst_ip}\n\n"
                f"Summary:\n{alert.summary}\n\n"
                f"Evidence:\n{alert.evidence}\n"
            )
            msg.attach(MIMEText(body, "plain"))

            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                server.starttls()
                server.login(self.sender_email, self.sender_password)
                server.send_message(msg)

            logger.info("Email notification sent for %s alert to %s", alert.severity, self.recipient_email)
        except Exception as e:
            logger.error("Failed to send email notification: %s", e)

    def update_settings(
        self,
        enabled: Optional[bool] = None,
        recipient: Optional[str] = None,
        smtp_host: Optional[str] = None,
        smtp_port: Optional[int] = None,
        sender_email: Optional[str] = None,
        sender_password: Optional[str] = None,
        min_severity: Optional[str] = None,
    ):
        if enabled is not None:
            self.enabled = enabled
        if recipient is not None:
            self.recipient_email = recipient
        if smtp_host is not None:
            self.smtp_host = smtp_host
        if smtp_port is not None:
            self.smtp_port = smtp_port
        if sender_email is not None:
            self.sender_email = sender_email
        if sender_password is not None:
            self.sender_password = sender_password
        if min_severity is not None:
            self.min_severity = min_severity

    def get_settings(self) -> dict:
        return {
            "enabled": self.enabled,
            "smtp_host": self.smtp_host,
            "smtp_port": self.smtp_port,
            "sender_email": self.sender_email,
            "recipient_email": self.recipient_email,
            "min_severity": self.min_severity,
        }
