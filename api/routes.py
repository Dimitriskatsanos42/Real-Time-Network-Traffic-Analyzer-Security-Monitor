"""
REST API Routes.

Παρέχει endpoints για:
  - Στατιστικά & monitoring data
  - Packet capture control
  - GeoIP & blacklist management
  - CSV/PDF exports
  - JWT authentication

Τα περισσότερα endpoints απαιτούν JWT token (Authorization: Bearer <token>).
Δημόσια: /api/health, /api/auth/login
"""

import os
from datetime import datetime, timedelta, timezone

from flask import Blueprint, Response, current_app, jsonify, request
from sqlalchemy import func

from alerts.manager import AlertManager
from auth.jwt_auth import (
    authenticate_user,
    clear_failed_logins,
    create_token,
    jwt_required,
    login_is_locked,
    record_failed_login,
    roles_required,
    validate_password,
)
from extensions import db
from models import Alert, DNSQuery, LoginAttempt, PacketRecord, TopIP, User, UserProfile
from reports.csv_export import (
    export_alerts_csv,
    export_dns_csv,
    export_packets_csv,
    export_top_ips_csv,
)
from reports.pdf_report import generate_security_report
from services.blacklist import BlacklistService
from services.geoip import GeoIPService
from services.crypto import decrypt_value, encrypt_value

api_bp = Blueprint("api", __name__, url_prefix="/api")


def _valid_username(username):
    return (
        3 <= len(username) <= 80
        and username.replace("_", "").replace("-", "").isalnum()
    )


# ══════════════════════════════════════════════════════════════════
# PUBLIC ENDPOINTS (χωρίς JWT)
# ══════════════════════════════════════════════════════════════════

@api_bp.route("/health")
def health():
    """Health check — δημόσιο endpoint για monitoring/load balancers."""
    return jsonify({
        "status": "ok",
        "service": "network-traffic-analyzer",
        "version": "2.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })


@api_bp.route("/auth/login", methods=["POST"])
def login():
    """
    JWT Authentication — δημόσιο login endpoint.

    Body: {"username": "admin", "password": "admin123"}
    Returns: {"token": "...", "user": {...}}
    """
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")
    source_ip = request.remote_addr

    if login_is_locked(username, source_ip):
        return jsonify({"error": "Too many failed attempts. Try again later."}), 429

    user = authenticate_user(username, password)
    if not user:
        record_failed_login(username, source_ip)
        return jsonify({"error": "Invalid credentials"}), 401

    clear_failed_logins(username, source_ip)
    token = create_token(user.id, user.username, user.role)
    return jsonify({
        "token": token,
        "user": user.to_dict(),
    })


@api_bp.route("/auth/register", methods=["POST"])
def register():
    """Create a viewer account with optional encrypted profile fields."""
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip().lower()
    password = data.get("password", "")
    if not _valid_username(username):
        return jsonify({"error": "Username must contain 3-80 letters, numbers, '_' or '-'"}), 400
    if not validate_password(password):
        return jsonify({"error": "Password must be 12+ characters with upper, lower, number and symbol"}), 400
    if User.query.filter_by(username=username).first():
        return jsonify({"error": "Username already exists"}), 409

    user = User(username=username, role="viewer")
    user.set_password(password)
    db.session.add(user)
    db.session.flush()
    _save_profile(user, data)
    db.session.commit()
    return jsonify({"user": user.to_dict()}), 201


@api_bp.route("/auth/me", methods=["GET", "PATCH"])
@jwt_required
def current_user_profile():
    user = db.session.get(User, int(request.current_user["sub"]))
    if not user:
        return jsonify({"error": "User not found"}), 404
    if request.method == "PATCH":
        data = request.get_json(silent=True) or {}
        if "password" in data:
            if not validate_password(data["password"]):
                return jsonify({"error": "Password must be 12+ characters with upper, lower, number and symbol"}), 400
            user.set_password(data["password"])
        _save_profile(user, data)
        db.session.commit()
    return jsonify(_profile_dict(user))


@api_bp.route("/users", methods=["GET", "POST"])
@jwt_required
@roles_required("admin")
def users():
    if request.method == "GET":
        return jsonify([user.to_dict() for user in User.query.order_by(User.id).all()])

    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip().lower()
    password = data.get("password", "")
    role = data.get("role", "viewer")
    if not _valid_username(username):
        return jsonify({"error": "Username must contain 3-80 letters, numbers, '_' or '-'"}), 400
    if role not in {"admin", "analyst", "viewer"}:
        return jsonify({"error": "Invalid role"}), 400
    if User.query.filter_by(username=username).first():
        return jsonify({"error": "Username already exists"}), 409
    if not validate_password(password):
        return jsonify({"error": "Password must be 12+ characters with upper, lower, number and symbol"}), 400
    user = User(username=username, role=role)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    return jsonify({"user": user.to_dict()}), 201


def _save_profile(user, data):
    profile = user.profile or UserProfile(user_id=user.id)
    for field in ("email", "full_name", "phone", "notes"):
        if field in data:
            setattr(profile, f"{field}_encrypted", encrypt_value(str(data[field])))
    if profile not in db.session:
        db.session.add(profile)


def _profile_dict(user):
    profile = user.profile
    return {
        "user": user.to_dict(),
        "profile": {
            "email": decrypt_value(profile.email_encrypted) if profile else None,
            "full_name": decrypt_value(profile.full_name_encrypted) if profile else None,
            "phone": decrypt_value(profile.phone_encrypted) if profile else None,
            "notes": decrypt_value(profile.notes_encrypted) if profile else None,
        },
    }


# ══════════════════════════════════════════════════════════════════
# PROTECTED ENDPOINTS (απαιτούν JWT)
# ══════════════════════════════════════════════════════════════════

@api_bp.route("/stats")
@jwt_required
def stats():
    """Συνολικά στατιστικά συστήματος."""
    total_packets = PacketRecord.query.count()
    total_alerts = Alert.query.count()
    unack_alerts = Alert.query.filter_by(acknowledged=False).count()
    total_dns = DNSQuery.query.count()
    suspicious_dns = DNSQuery.query.filter_by(is_suspicious=True).count()
    failed_logins = LoginAttempt.query.filter_by(success=False).count()
    brute_force_alerts = Alert.query.filter_by(alert_type="brute_force").count()
    blacklist_hits = Alert.query.filter_by(alert_type="blacklist").count()

    one_hour_ago = datetime.now(timezone.utc) - timedelta(hours=1)
    recent_packets = PacketRecord.query.filter(
        PacketRecord.timestamp >= one_hour_ago
    ).count()

    protocols = (
        db.session.query(PacketRecord.protocol, func.count(PacketRecord.id))
        .group_by(PacketRecord.protocol)
        .all()
    )

    return jsonify({
        "total_packets": total_packets,
        "packets_last_hour": recent_packets,
        "total_alerts": total_alerts,
        "unacknowledged_alerts": unack_alerts,
        "total_dns_queries": total_dns,
        "suspicious_dns_queries": suspicious_dns,
        "failed_logins": failed_logins,
        "brute_force_alerts": brute_force_alerts,
        "blacklist_hits": blacklist_hits,
        "protocols": {p: c for p, c in protocols},
    })


@api_bp.route("/packets")
@jwt_required
def packets():
    """Πρόσφατα captured packets."""
    limit = min(int(request.args.get("limit", 100)), 500)
    records = (
        PacketRecord.query.order_by(PacketRecord.timestamp.desc()).limit(limit).all()
    )
    return jsonify([r.to_dict() for r in records])


@api_bp.route("/top-ips")
@jwt_required
def top_ips():
    """Top IPs ανά κίνηση (με GeoIP & blacklist info)."""
    limit = min(int(request.args.get("limit", 20)), 100)
    records = TopIP.query.order_by(TopIP.packet_count.desc()).limit(limit).all()
    return jsonify([r.to_dict() for r in records])


@api_bp.route("/dns")
@jwt_required
def dns_queries():
    """DNS queries — προαιρετικά μόνο suspicious."""
    limit = min(int(request.args.get("limit", 50)), 200)
    suspicious_only = request.args.get("suspicious", "false").lower() == "true"

    query = DNSQuery.query
    if suspicious_only:
        query = query.filter_by(is_suspicious=True)

    records = query.order_by(DNSQuery.timestamp.desc()).limit(limit).all()
    return jsonify([r.to_dict() for r in records])


@api_bp.route("/alerts")
@jwt_required
def alerts():
    """Security alerts."""
    limit = min(int(request.args.get("limit", 50)), 200)
    unack_only = request.args.get("unacknowledged", "false").lower() == "true"

    query = Alert.query
    if unack_only:
        query = query.filter_by(acknowledged=False)

    records = query.order_by(Alert.timestamp.desc()).limit(limit).all()
    return jsonify([r.to_dict() for r in records])


@api_bp.route("/alerts/<int:alert_id>/acknowledge", methods=["POST"])
@jwt_required
def acknowledge_alert(alert_id):
    """Acknowledge ενός alert."""
    if AlertManager.acknowledge(alert_id):
        return jsonify({"success": True, "alert_id": alert_id})
    return jsonify({"success": False, "error": "Alert not found"}), 404


@api_bp.route("/login-attempts")
@jwt_required
def login_attempts():
    """Καταγραφές failed login / brute-force attempts."""
    limit = min(int(request.args.get("limit", 50)), 200)
    failed_only = request.args.get("failed", "true").lower() == "true"

    query = LoginAttempt.query
    if failed_only:
        query = query.filter_by(success=False)

    records = query.order_by(LoginAttempt.timestamp.desc()).limit(limit).all()
    return jsonify([r.to_dict() for r in records])


# ── GeoIP ─────────────────────────────────────────────────────────

@api_bp.route("/geoip/<ip>")
@jwt_required
def geoip_lookup(ip):
    """GeoIP lookup για συγκεκριμένη IP."""
    geoip = GeoIPService(
        db_path=current_app.config.get("GEOIP_DB_PATH"),
        fallback_api=current_app.config.get("GEOIP_FALLBACK_API"),
    )
    result = geoip.lookup(ip)
    result["ip_address"] = ip
    return jsonify(result)


# ── Blacklist Management ──────────────────────────────────────────

@api_bp.route("/blacklist")
@jwt_required
def get_blacklist():
    """Λίστα ενεργών blacklist entries."""
    service = BlacklistService(current_app.config.get("BLACKLIST_FILE"))
    service.load()
    return jsonify([e.to_dict() for e in service.get_all()])


@api_bp.route("/blacklist", methods=["POST"])
@jwt_required
def add_blacklist():
    """Προσθήκη IP στη blacklist. Body: {"ip": "...", "reason": "..."}"""
    data = request.get_json(silent=True) or {}
    ip = data.get("ip", "")
    reason = data.get("reason", "Manual entry")

    if not ip:
        return jsonify({"error": "IP address required"}), 400

    service = BlacklistService(current_app.config.get("BLACKLIST_FILE"))
    service.load()
    added = service.add(ip, reason=reason)
    return jsonify({"success": added, "ip": ip})


@api_bp.route("/blacklist/<ip>", methods=["DELETE"])
@jwt_required
def remove_blacklist(ip):
    """Αφαίρεση IP από τη blacklist."""
    service = BlacklistService(current_app.config.get("BLACKLIST_FILE"))
    service.load()
    removed = service.remove(ip)
    return jsonify({"success": removed, "ip": ip})


# ── Capture Control ───────────────────────────────────────────────

@api_bp.route("/capture/status")
@jwt_required
def capture_status():
    """Κατάσταση packet capture."""
    sniffer = current_app.config.get("SNIFFER")
    return jsonify({
        "running": sniffer.is_running if sniffer else False,
        "interface": current_app.config.get("CAPTURE_INTERFACE"),
    })


@api_bp.route("/capture/start", methods=["POST"])
@jwt_required
def start_capture():
    """Έναρξη packet capture."""
    sniffer = current_app.config.get("SNIFFER")
    if not sniffer:
        return jsonify({"success": False, "error": "Sniffer not initialized"}), 500
    started = sniffer.start()
    return jsonify({"success": started, "running": sniffer.is_running})


@api_bp.route("/capture/stop", methods=["POST"])
@jwt_required
def stop_capture():
    """Διακοπή packet capture."""
    sniffer = current_app.config.get("SNIFFER")
    if not sniffer:
        return jsonify({"success": False, "error": "Sniffer not initialized"}), 500
    sniffer.stop()
    return jsonify({"success": True, "running": sniffer.is_running})


# ── Export: CSV ───────────────────────────────────────────────────

@api_bp.route("/export/csv/<data_type>")
@jwt_required
def export_csv(data_type):
    """
    Εξαγωγή δεδομένων σε CSV.
    data_type: packets | alerts | dns | top-ips
    """
    exporters = {
        "packets": export_packets_csv,
        "alerts": export_alerts_csv,
        "dns": export_dns_csv,
        "top-ips": export_top_ips_csv,
    }

    exporter = exporters.get(data_type)
    if not exporter:
        return jsonify({"error": f"Unknown export type: {data_type}"}), 400

    content, filename = exporter()
    return Response(
        content,
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


# ── Export: PDF Report ────────────────────────────────────────────

@api_bp.route("/export/pdf")
@jwt_required
def export_pdf():
    """Δημιουργία PDF security report."""
    days = min(int(request.args.get("days", 7)), 90)
    reports_dir = current_app.config.get("REPORTS_DIR", "reports")
    os.makedirs(reports_dir, exist_ok=True)

    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    output_path = os.path.join(reports_dir, f"security_report_{ts}.pdf")
    generate_security_report(output_path, days=days)

    with open(output_path, "rb") as f:
        pdf_data = f.read()

    return Response(
        pdf_data,
        mimetype="application/pdf",
        headers={
            "Content-Disposition": f"attachment; filename=security_report_{ts}.pdf"
        },
    )
