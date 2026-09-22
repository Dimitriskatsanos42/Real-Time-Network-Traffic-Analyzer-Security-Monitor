"""
Alert Manager — Δημιουργία και διαχείριση security alerts.

Κεντρικό σημείο για όλα τα detection modules να δημιουργούν
ειδοποιήσεις με consistent format και severity levels.
"""

import logging

from extensions import db
from models import Alert

logger = logging.getLogger(__name__)


class AlertManager:
    """Διαχείριση security alerts."""

    def create_alert(self, severity, alert_type, source_ip, message, country=None):
        """
        Δημιουργεί νέο alert και το αποθηκεύει στη βάση.

        Args:
            severity: low | medium | high | critical
            alert_type: port_scan | brute_force | failed_login | blacklist | suspicious_dns
            source_ip: IP πηγής της απειλής
            message: Περιγραφή του alert
            country: Χώρα (από GeoIP lookup)
        """
        alert = Alert(
            severity=severity,
            alert_type=alert_type,
            source_ip=source_ip,
            message=message,
            country=country,
        )
        db.session.add(alert)
        db.session.commit()
        logger.warning(
            "[%s] %s - %s (%s): %s",
            severity.upper(),
            alert_type,
            source_ip,
            country or "Unknown",
            message,
        )
        return alert

    @staticmethod
    def acknowledge(alert_id):
        """Σημειώνει alert ως acknowledged."""
        alert = Alert.query.get(alert_id)
        if alert:
            alert.acknowledged = True
            db.session.commit()
            return True
        return False

    @staticmethod
    def get_unacknowledged(limit=50):
        """Επιστρέφει μη-acknowledged alerts."""
        return (
            Alert.query.filter_by(acknowledged=False)
            .order_by(Alert.timestamp.desc())
            .limit(limit)
            .all()
        )
