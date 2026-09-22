import sys
from uuid import uuid4
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app import create_app


def test_create_app_smoke():
    app = create_app()
    assert app is not None


def test_health_endpoint():
    app = create_app()
    client = app.test_client()
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.get_json()["status"] == "ok"


def test_dashboard_template_loads_deferred_script():
    app = create_app()
    client = app.test_client()
    response = client.get("/")
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert 'dashboard.js' in html
    assert 'defer' in html


def test_login_returns_token_accepted_by_protected_endpoint():
    app = create_app()
    client = app.test_client()

    response = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "admin123"},
    )

    assert response.status_code == 200
    token = response.get_json()["token"]
    protected_response = client.get(
        "/api/stats",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert protected_response.status_code == 200


def test_register_and_encrypted_profile_are_user_owned():
    app = create_app()
    client = app.test_client()
    username = f"profile_{uuid4().hex[:10]}"
    response = client.post(
        "/api/auth/register",
        json={
            "username": username,
            "password": "StrongPass!123",
            "email": "profile@example.com",
            "full_name": "Profile User",
        },
    )
    assert response.status_code == 201

    token = client.post(
        "/api/auth/login",
        json={"username": username, "password": "StrongPass!123"},
    ).get_json()["token"]
    profile = client.get(
        "/api/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert profile.status_code == 200
    assert profile.get_json()["profile"]["email"] == "profile@example.com"


def test_viewer_cannot_manage_users():
    app = create_app()
    client = app.test_client()
    username = f"viewer_{uuid4().hex[:10]}"
    client.post(
        "/api/auth/register",
        json={"username": username, "password": "StrongPass!123"},
    )
    token = client.post(
        "/api/auth/login",
        json={"username": username, "password": "StrongPass!123"},
    ).get_json()["token"]
    response = client.get(
        "/api/users",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 403
