"""
PDF Security Report Generator.

Δημιουργεί επαγγελματική αναφορά ασφαλείας σε PDF format
με στατιστικά, alerts, top IPs και DNS analysis.
"""

import os
from datetime import datetime, timedelta, timezone

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from models import Alert, DNSQuery, PacketRecord, TopIP


def generate_security_report(output_path, days=7):
    """
    Δημιουργεί PDF αναφορά ασφαλείας για τις τελευταίες N ημέρες.

    Περιεχόμενα:
      - Executive Summary (στατιστικά)
      - Security Alerts table
      - Top IPs table
      - Suspicious DNS queries
    """
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    doc = SimpleDocTemplate(output_path, pagesize=A4, topMargin=2 * cm, bottomMargin=2 * cm)
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "CustomTitle",
        parent=styles["Heading1"],
        fontSize=18,
        spaceAfter=20,
        textColor=colors.HexColor("#1e3a5f"),
    )
    heading_style = ParagraphStyle(
        "CustomHeading",
        parent=styles["Heading2"],
        fontSize=13,
        spaceBefore=16,
        spaceAfter=8,
        textColor=colors.HexColor("#2563eb"),
    )

    since = datetime.now(timezone.utc) - timedelta(days=days)
    elements = []

    # ── Header ────────────────────────────────────────────────────────
    elements.append(Paragraph("Network Security Monitor — Report", title_style))
    elements.append(
        Paragraph(
            f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} | "
            f"Period: Last {days} days",
            styles["Normal"],
        )
    )
    elements.append(Spacer(1, 0.5 * cm))

    # ── Executive Summary ─────────────────────────────────────────────
    total_packets = PacketRecord.query.filter(PacketRecord.timestamp >= since).count()
    total_alerts = Alert.query.filter(Alert.timestamp >= since).count()
    critical_alerts = Alert.query.filter(
        Alert.timestamp >= since, Alert.severity == "critical"
    ).count()
    suspicious_dns = DNSQuery.query.filter(
        DNSQuery.timestamp >= since, DNSQuery.is_suspicious.is_(True)
    ).count()

    summary_data = [
        ["Metric", "Value"],
        ["Total Packets Captured", str(total_packets)],
        ["Security Alerts", str(total_alerts)],
        ["Critical Alerts", str(critical_alerts)],
        ["Suspicious DNS Queries", str(suspicious_dns)],
    ]
    elements.append(Paragraph("Executive Summary", heading_style))
    elements.append(_styled_table(summary_data))
    elements.append(Spacer(1, 0.3 * cm))

    # ── Security Alerts ─────────────────────────────────────────────
    alerts = (
        Alert.query.filter(Alert.timestamp >= since)
        .order_by(Alert.timestamp.desc())
        .limit(30)
        .all()
    )
    elements.append(Paragraph("Security Alerts", heading_style))
    if alerts:
        alert_data = [["Time", "Severity", "Type", "Source IP", "Country", "Message"]]
        for a in alerts:
            alert_data.append([
                a.timestamp.strftime("%Y-%m-%d %H:%M") if a.timestamp else "-",
                a.severity.upper(),
                a.alert_type,
                a.source_ip or "-",
                a.country or "-",
                (a.message or "")[:60],
            ])
        elements.append(_styled_table(alert_data))
    else:
        elements.append(Paragraph("No alerts in this period.", styles["Normal"]))

    # ── Top IPs ───────────────────────────────────────────────────────
    top_ips = TopIP.query.order_by(TopIP.packet_count.desc()).limit(15).all()
    elements.append(Paragraph("Top IP Addresses", heading_style))
    if top_ips:
        ip_data = [["IP Address", "Country", "Packets", "Bytes", "Blacklisted"]]
        for ip in top_ips:
            ip_data.append([
                ip.ip_address,
                ip.country or "Unknown",
                str(ip.packet_count),
                str(ip.byte_count),
                "YES" if ip.is_blacklisted else "No",
            ])
        elements.append(_styled_table(ip_data))
    else:
        elements.append(Paragraph("No IP data available.", styles["Normal"]))

    # ── Suspicious DNS ────────────────────────────────────────────────
    dns_records = (
        DNSQuery.query.filter(DNSQuery.is_suspicious.is_(True), DNSQuery.timestamp >= since)
        .order_by(DNSQuery.timestamp.desc())
        .limit(20)
        .all()
    )
    elements.append(Paragraph("Suspicious DNS Queries", heading_style))
    if dns_records:
        dns_data = [["Time", "Source IP", "Query", "Type"]]
        for d in dns_records:
            dns_data.append([
                d.timestamp.strftime("%Y-%m-%d %H:%M") if d.timestamp else "-",
                d.src_ip,
                (d.query_name or "")[:50],
                d.query_type,
            ])
        elements.append(_styled_table(dns_data))
    else:
        elements.append(Paragraph("No suspicious DNS queries detected.", styles["Normal"]))

    doc.build(elements)
    return output_path


def _styled_table(data):
    """Δημιουργεί styled ReportLab table."""
    table = Table(data, repeatRows=1)
    table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e3a5f")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f0f4f8")]),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ])
    )
    return table
