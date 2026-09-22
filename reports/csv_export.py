"""
CSV Export Module.

Εξαγωγή δεδομένων σε CSV format για ανάλυση σε Excel, SIEM, κ.λπ.
"""

import csv
import io
from datetime import datetime, timezone

from models import Alert, DNSQuery, PacketRecord, TopIP


def _csv_response(rows, filename):
    """Μετατρέπει λίστα dicts σε CSV string με UTF-8 BOM για Excel."""
    if not rows:
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["No data available"])
        return output.getvalue(), filename

    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=rows[0].keys())
    writer.writeheader()
    writer.writerows(rows)
    return "\ufeff" + output.getvalue(), filename


def export_packets_csv(limit=1000):
    """Εξαγωγή captured packets σε CSV."""
    records = (
        PacketRecord.query.order_by(PacketRecord.timestamp.desc()).limit(limit).all()
    )
    rows = [r.to_dict() for r in records]
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    return _csv_response(rows, f"packets_{ts}.csv")


def export_alerts_csv(limit=1000):
    """Εξαγωγή security alerts σε CSV."""
    records = Alert.query.order_by(Alert.timestamp.desc()).limit(limit).all()
    rows = [r.to_dict() for r in records]
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    return _csv_response(rows, f"alerts_{ts}.csv")


def export_dns_csv(limit=1000):
    """Εξαγωγή DNS queries σε CSV."""
    records = DNSQuery.query.order_by(DNSQuery.timestamp.desc()).limit(limit).all()
    rows = [r.to_dict() for r in records]
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    return _csv_response(rows, f"dns_queries_{ts}.csv")


def export_top_ips_csv(limit=100):
    """Εξαγωγή Top IPs σε CSV."""
    records = TopIP.query.order_by(TopIP.packet_count.desc()).limit(limit).all()
    rows = [r.to_dict() for r in records]
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    return _csv_response(rows, f"top_ips_{ts}.csv")
