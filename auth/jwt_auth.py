"""
JWT Authentication Module.

Παρέχει token-based authentication για το REST API:
  - Δημιουργία JWT token μετά από επιτυχημένο login
  - Decorator @jwt_required για προστασία endpoints
  - Επαλήθευση token σε κάθε protected request
"""

import functools
import re
import threading
from datetime import datetime, timedelta, timezone

import jwt
from flask import current_app, jsonify, request

from models import User


_failed_logins = {}
_failed_logins_lock = threading.Lock()
PASSWORD_POLICY = re.compile(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z\d]).{12,128}$")


def validate_password(password):
    """Require a password with enough length and character variety."""
    return isinstance(password, str) and bool(PASSWORD_POLICY.fullmatch(password))


def _login_key(username, source_ip):
    return (username.strip().lower(), source_ip or "unknown")


def login_is_locked(username, source_ip):
    now = datetime.now(timezone.utc).timestamp()
    with _failed_logins_lock:
        entry = _failed_logins.get(_login_key(username, source_ip))
        if not entry:
            return False
        if entry["locked_until"] > now:
            return True
        _failed_logins.pop(_login_key(username, source_ip), None)
        return False


def record_failed_login(username, source_ip):
    now = datetime.now(timezone.utc).timestamp()
    key = _login_key(username, source_ip)
    with _failed_logins_lock:
        entry = _failed_logins.setdefault(key, {"attempts": 0, "locked_until": 0})
        entry["attempts"] += 1
        if entry["attempts"] >= current_app.config["LOGIN_MAX_ATTEMPTS"]:
            entry["locked_until"] = now + current_app.config["LOGIN_LOCKOUT_SECONDS"]


def clear_failed_logins(username, source_ip):
    with _failed_logins_lock:
        _failed_logins.pop(_login_key(username, source_ip), None)


def create_token(user_id, username, role):
    """
    Δημιουργεί signed JWT token.

    Payload περιέχει: user_id, username, role, exp (expiration).
    """
    issued_at = datetime.now(timezone.utc)
    expiration = issued_at + current_app.config["JWT_EXPIRATION"]
    payload = {
        "sub": str(user_id),
        "username": username,
        "role": role,
        "iat": int(issued_at.timestamp()),
        "exp": int(expiration.timestamp()),
    }
    return jwt.encode(
        payload,
        current_app.config["JWT_SECRET_KEY"],
        algorithm=current_app.config["JWT_ALGORITHM"],
    )


def verify_token(token):
    """
    Επαληθεύει JWT token και επιστρέφει το decoded payload.
    Raises jwt.InvalidTokenError αν το token είναι άκυρο/ληγμένο.
    """
    return jwt.decode(
        token,
        current_app.config["JWT_SECRET_KEY"],
        algorithms=[current_app.config["JWT_ALGORITHM"]],
    )


def jwt_required(f):
    """
    Decorator που απαιτεί valid JWT token στο Authorization header.

    Χρήση:
        @api_bp.route("/protected")
        @jwt_required
        def protected_endpoint():
            ...
    """

    @functools.wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")

        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "Missing or invalid Authorization header"}), 401

        token = auth_header.split(" ", 1)[1]
        try:
            payload = verify_token(token)
            request.current_user = payload
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token has expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401

        return f(*args, **kwargs)

    return decorated


def roles_required(*roles):
    """Protect an endpoint with one or more allowed roles."""
    def decorator(f):
        @functools.wraps(f)
        def decorated(*args, **kwargs):
            payload = getattr(request, "current_user", {})
            if payload.get("role") not in roles:
                return jsonify({"error": "Insufficient permissions"}), 403
            return f(*args, **kwargs)
        return decorated
    return decorator


def authenticate_user(username, password):
    """
    Επαληθεύει credentials και επιστρέφει User object ή None.
    """
    user = User.query.filter_by(username=username).first()
    if user and user.check_password(password):
        return user
    return None
