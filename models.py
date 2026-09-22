"""
Database Models (SQLAlchemy ORM).

Ορίζει όλους τους πίνακες της βάσης δεδομένων:
πακέτα, DNS, alerts, GeoIP cache, blacklist, login attempts, χρήστες.
"""

from datetime import datetime, timezone

from extensions import db
from werkzeug.security import check_password_hash, generate_password_hash


def utcnow():
    """Επιστρέφει τρέχουσα UTC ώρα (timezone-aware)."""
    return datetime.now(timezone.utc)


class User(db.Model):
    """Χρήστης για JWT authentication στο REST API."""

    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), default="admin")  # admin, analyst, viewer
    created_at = db.Column(db.DateTime, default=utcnow)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def to_dict(self):
        return {
            "id": self.id,
            "username": self.username,
            "role": self.role,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class UserProfile(db.Model):
    """Encrypted profile data owned by one user."""

    __tablename__ = "user_profiles"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), unique=True, nullable=False)
    email_encrypted = db.Column(db.Text)
    full_name_encrypted = db.Column(db.Text)
    phone_encrypted = db.Column(db.Text)
    notes_encrypted = db.Column(db.Text)
    updated_at = db.Column(db.DateTime, default=utcnow, onupdate=utcnow)

    user = db.relationship("User", backref=db.backref("profile", uselist=False))


class PacketRecord(db.Model):
    """Καταγραφή ενός captured network packet."""

    __tablename__ = "packets"

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=utcnow, index=True)
    src_ip = db.Column(db.String(45), index=True)
    dst_ip = db.Column(db.String(45), index=True)
    src_port = db.Column(db.Integer)
    dst_port = db.Column(db.Integer)
    protocol = db.Column(db.String(10), index=True)
    length = db.Column(db.Integer, default=0)
    flags = db.Column(db.String(20))
    src_country = db.Column(db.String(64))
    dst_country = db.Column(db.String(64))

    def to_dict(self):
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "length": self.length,
            "flags": self.flags,
            "src_country": self.src_country,
            "dst_country": self.dst_country,
        }


class DNSQuery(db.Model):
    """DNS query που εντοπίστηκε στο network traffic."""

    __tablename__ = "dns_queries"

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=utcnow, index=True)
    src_ip = db.Column(db.String(45), index=True)
    query_name = db.Column(db.String(255), index=True)
    query_type = db.Column(db.String(20))
    is_suspicious = db.Column(db.Boolean, default=False)
    src_country = db.Column(db.String(64))

    def to_dict(self):
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "src_ip": self.src_ip,
            "query_name": self.query_name,
            "query_type": self.query_type,
            "is_suspicious": self.is_suspicious,
            "src_country": self.src_country,
        }


class TopIP(db.Model):
    """Στατιστικά κίνησης ανά IP address (Top Talkers)."""

    __tablename__ = "top_ips"

    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), unique=True, index=True)
    packet_count = db.Column(db.Integer, default=0)
    byte_count = db.Column(db.BigInteger, default=0)
    last_seen = db.Column(db.DateTime, default=utcnow)
    country = db.Column(db.String(64))
    country_code = db.Column(db.String(4))
    is_blacklisted = db.Column(db.Boolean, default=False)

    def to_dict(self):
        return {
            "ip_address": self.ip_address,
            "packet_count": self.packet_count,
            "byte_count": self.byte_count,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "country": self.country,
            "country_code": self.country_code,
            "is_blacklisted": self.is_blacklisted,
        }


class Alert(db.Model):
    """Security alert — ειδοποίηση για ύποπτη δραστηριότητα."""

    __tablename__ = "alerts"

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=utcnow, index=True)
    severity = db.Column(db.String(20), index=True)  # low, medium, high, critical
    alert_type = db.Column(db.String(50), index=True)
    source_ip = db.Column(db.String(45), index=True)
    message = db.Column(db.Text)
    acknowledged = db.Column(db.Boolean, default=False)
    country = db.Column(db.String(64))

    def to_dict(self):
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "severity": self.severity,
            "alert_type": self.alert_type,
            "source_ip": self.source_ip,
            "message": self.message,
            "acknowledged": self.acknowledged,
            "country": self.country,
        }


class IPGeoCache(db.Model):
    """Cache αποτελεσμάτων GeoIP lookup — αποφεύγει επαναλαμβανόμενα API calls."""

    __tablename__ = "ip_geo_cache"

    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), unique=True, index=True)
    country = db.Column(db.String(64))
    country_code = db.Column(db.String(4))
    city = db.Column(db.String(128))
    isp = db.Column(db.String(256))
    updated_at = db.Column(db.DateTime, default=utcnow)

    def to_dict(self):
        return {
            "ip_address": self.ip_address,
            "country": self.country,
            "country_code": self.country_code,
            "city": self.city,
            "isp": self.isp,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class BlacklistEntry(db.Model):
    """IP στη μαύρη λίστα — γνωστή κακόβουλη ή αποκλεισμένη διεύθυνση."""

    __tablename__ = "blacklist"

    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), unique=True, index=True)
    reason = db.Column(db.String(255))
    source = db.Column(db.String(50), default="manual")  # manual, file, api
    added_at = db.Column(db.DateTime, default=utcnow)
    active = db.Column(db.Boolean, default=True)

    def to_dict(self):
        return {
            "id": self.id,
            "ip_address": self.ip_address,
            "reason": self.reason,
            "source": self.source,
            "added_at": self.added_at.isoformat() if self.added_at else None,
            "active": self.active,
        }


class LoginAttempt(db.Model):
    """Καταγραφή αποτυχημένης προσπάθειας σύνδεσης (failed login)."""

    __tablename__ = "login_attempts"

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=utcnow, index=True)
    src_ip = db.Column(db.String(45), index=True)
    dst_ip = db.Column(db.String(45))
    dst_port = db.Column(db.Integer, index=True)
    service = db.Column(db.String(30))  # SSH, RDP, FTP, κ.λπ.
    success = db.Column(db.Boolean, default=False)
    country = db.Column(db.String(64))

    def to_dict(self):
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "service": self.service,
            "success": self.success,
            "country": self.country,
        }
