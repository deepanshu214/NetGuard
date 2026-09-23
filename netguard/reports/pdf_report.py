"""PDF Report Generator for NetGuard security audit reports."""
import io
import time
from typing import Any, Dict, List

from fpdf import FPDF


class NetGuardReport(FPDF):
    def header(self):
        self.set_font("Helvetica", "B", 16)
        self.cell(0, 10, "NetGuard Security Report", align="C", new_x="LMARGIN", new_y="NEXT")
        self.set_font("Helvetica", "", 9)
        self.set_text_color(100, 100, 100)
        self.cell(0, 6, f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}", align="C", new_x="LMARGIN", new_y="NEXT")
        self.ln(4)
        self.set_draw_color(56, 189, 248)
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(6)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(150, 150, 150)
        self.cell(0, 10, f"NetGuard NIDS - Page {self.page_no()}/{{nb}}", align="C")


def generate_pdf_report(
    alerts: List[Dict[str, Any]],
    stats: Dict[str, Any],
    metrics_summary: Dict[str, Any],
) -> bytes:
    """Generates a PDF report and returns it as bytes."""
    pdf = NetGuardReport()
    pdf.alias_nb_pages()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=20)

    # --- Executive Summary ---
    pdf.set_font("Helvetica", "B", 13)
    pdf.set_text_color(30, 30, 30)
    pdf.cell(0, 8, "1. Executive Summary", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(3)

    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(50, 50, 50)
    total = stats.get("total", 0)
    by_sev = stats.get("by_severity", {})
    critical = by_sev.get("CRITICAL", 0)
    high = by_sev.get("HIGH", 0)
    medium = by_sev.get("MEDIUM", 0)
    low = by_sev.get("LOW", 0)

    pdf.multi_cell(0, 6, (
        f"Total security events detected: {total}\n"
        f"  - Critical: {critical}    High: {high}    Medium: {medium}    Low: {low}\n"
        f"Total packets processed: {metrics_summary.get('total_packets', 'N/A')}\n"
        f"Total data volume: {metrics_summary.get('total_bytes_str', 'N/A')}\n"
        f"Monitoring uptime: {metrics_summary.get('uptime', 'N/A')}"
    ))
    pdf.ln(6)

    # --- Alert Breakdown by Type ---
    pdf.set_font("Helvetica", "B", 13)
    pdf.set_text_color(30, 30, 30)
    pdf.cell(0, 8, "2. Alert Breakdown by Type", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(3)

    by_type = stats.get("by_type", {})
    if by_type:
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_fill_color(240, 240, 240)
        pdf.cell(95, 7, "Attack Type", border=1, fill=True)
        pdf.cell(40, 7, "Count", border=1, fill=True, new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 9)
        for atype, count in sorted(by_type.items(), key=lambda x: x[1], reverse=True):
            pdf.cell(95, 7, atype, border=1)
            pdf.cell(40, 7, str(count), border=1, new_x="LMARGIN", new_y="NEXT")
    else:
        pdf.set_font("Helvetica", "I", 10)
        pdf.cell(0, 7, "No alerts recorded.", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(6)

    # --- Top Attacker IPs ---
    pdf.set_font("Helvetica", "B", 13)
    pdf.set_text_color(30, 30, 30)
    pdf.cell(0, 8, "3. Top Attacker Source IPs", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(3)

    ip_counts: Dict[str, int] = {}
    for a in alerts:
        ip = a.get("src_ip", "unknown")
        ip_counts[ip] = ip_counts.get(ip, 0) + 1
    top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]

    if top_ips:
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_fill_color(240, 240, 240)
        pdf.cell(80, 7, "Source IP", border=1, fill=True)
        pdf.cell(40, 7, "Alert Count", border=1, fill=True, new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 9)
        for ip, cnt in top_ips:
            pdf.cell(80, 7, ip, border=1)
            pdf.cell(40, 7, str(cnt), border=1, new_x="LMARGIN", new_y="NEXT")
    pdf.ln(6)

    # --- Recent Alerts Detail ---
    pdf.set_font("Helvetica", "B", 13)
    pdf.set_text_color(30, 30, 30)
    pdf.cell(0, 8, "4. Recent Alert Details (Last 25)", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(3)

    recent = alerts[:25]
    if recent:
        pdf.set_font("Helvetica", "B", 8)
        pdf.set_fill_color(240, 240, 240)
        pdf.cell(28, 6, "Time", border=1, fill=True)
        pdf.cell(18, 6, "Severity", border=1, fill=True)
        pdf.cell(30, 6, "Type", border=1, fill=True)
        pdf.cell(30, 6, "Source", border=1, fill=True)
        pdf.cell(30, 6, "Target", border=1, fill=True)
        pdf.cell(54, 6, "Summary", border=1, fill=True, new_x="LMARGIN", new_y="NEXT")

        pdf.set_font("Helvetica", "", 7)
        for a in recent:
            ts_str = time.strftime("%H:%M:%S", time.localtime(a.get("ts", 0)))
            pdf.cell(28, 6, ts_str, border=1)
            pdf.cell(18, 6, a.get("severity", ""), border=1)
            pdf.cell(30, 6, a.get("type", "")[:18], border=1)
            pdf.cell(30, 6, a.get("src_ip", ""), border=1)
            pdf.cell(30, 6, a.get("dst_ip", ""), border=1)
            pdf.cell(54, 6, a.get("summary", "")[:35], border=1, new_x="LMARGIN", new_y="NEXT")
    else:
        pdf.set_font("Helvetica", "I", 10)
        pdf.cell(0, 7, "No alerts to display.", new_x="LMARGIN", new_y="NEXT")

    return pdf.output()
