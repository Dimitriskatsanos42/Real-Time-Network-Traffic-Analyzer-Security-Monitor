"""
Network Traffic Analyzer & Security Monitor
===========================================
Entry point της εφαρμογής.

Εκκινεί:
  - Flask web server (dashboard + REST API)
  - Scapy packet sniffer (background thread)
  - Database initialization
  - Default admin user creation

Χρήση:
    python app.py
    # ή με Docker:
    docker-compose up
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, render_template

from api.routes import api_bp
from capture.processor import PacketProcessor
from capture.sniffer import PacketSniffer
from config import Config
from config.logging import setup_logging
from extensions import db
from models import User

logger = setup_logging()


def create_app(config_class=Config):
    """Application factory — δημιουργεί και ρυθμίζει το Flask app."""
    app = Flask(__name__)
    app.config.from_object(config_class)
    app.config.setdefault("APP_ROOT", os.path.dirname(os.path.abspath(__file__)))
    _validate_security_config(app)

    db.init_app(app)
    app.register_blueprint(api_bp)

    @app.route("/")
    def dashboard():
        return render_template("dashboard.html")

    with app.app_context():
        db.create_all()
        _ensure_default_user(app)
        os.makedirs(app.config.get("REPORTS_DIR", "reports"), exist_ok=True)
        blacklist_dir = os.path.dirname(app.config.get("BLACKLIST_FILE", "data/blacklist.txt")) or "."
        os.makedirs(blacklist_dir, exist_ok=True)

        processor = PacketProcessor(app)
        sniffer = PacketSniffer(processor, interface=app.config["CAPTURE_INTERFACE"])
        app.config["PROCESSOR"] = processor
        app.config["SNIFFER"] = sniffer

    return app


def _validate_security_config(app):
    """Reject development credentials when running in production."""
    if app.config.get("APP_ENV") != "production":
        return
    insecure_values = {
        "dev-secret-change-in-production-32-characters",
        "admin123",
    }
    if app.config.get("SECRET_KEY") in insecure_values:
        raise RuntimeError("Set a strong SECRET_KEY before starting in production")
    if app.config.get("JWT_SECRET_KEY") in insecure_values:
        raise RuntimeError("Set a strong JWT_SECRET_KEY before starting in production")
    if app.config.get("ADMIN_PASSWORD") in insecure_values:
        raise RuntimeError("Set a strong ADMIN_PASSWORD before starting in production")
    if not app.config.get("DATA_ENCRYPTION_KEY"):
        raise RuntimeError("Set DATA_ENCRYPTION_KEY before starting in production")


def _ensure_default_user(app):
    """
    Δημιουργεί default admin user αν δεν υπάρχει.
    Credentials από environment variables (ADMIN_USERNAME / ADMIN_PASSWORD).
    """
    if not User.query.filter_by(username=app.config["ADMIN_USERNAME"]).first():
        user = User(username=app.config["ADMIN_USERNAME"], role="admin")
        user.set_password(app.config["ADMIN_PASSWORD"])
        db.session.add(user)
        db.session.commit()
        logger.info("Default admin user created: %s", app.config["ADMIN_USERNAME"])


def main():
    """Κύρια συνάρτηση εκκίνησης."""
    app = create_app()

    if app.config.get("AUTO_START_CAPTURE"):
        sniffer = app.config.get("SNIFFER")
        if sniffer and sniffer.start():
            logger.info("Packet capture auto-started")
        else:
            logger.warning("Could not auto-start capture")

    host = app.config["FLASK_HOST"]
    port = app.config["FLASK_PORT"]
    debug = app.config["FLASK_DEBUG"]

    logger.info("=" * 60)
    logger.info("  Network Traffic Analyzer & Security Monitor v2.0")
    logger.info("  Dashboard: http://%s:%s", host, port)
    logger.info("  API Docs:  http://%s:%s/api/health", host, port)
    logger.info("=" * 60)

    app.run(host=host, port=port, debug=debug, use_reloader=False)


if __name__ == "__main__":
    main()
