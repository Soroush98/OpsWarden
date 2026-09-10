"""End-to-end route guards, exercised through the ASGI app with no network.

Regression test for a real bug: an edit to the approve route silently failed to apply, leaving
the endpoint unauthenticated while the code *looked* correct. Only a request-level test caught it.
"""
import os
import tempfile

os.environ.setdefault("OPSWARDEN_SESSION_SECRET", "test-secret-value")
os.environ.setdefault("OPSWARDEN_INGEST_TOKEN", "test-ingest-token")
os.environ.setdefault("OPSWARDEN_DB_PATH", os.path.join(tempfile.mkdtemp(), "test.db"))

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from opswarden_api.app import app  # noqa: E402
from opswarden_api.auth import SESSION_COOKIE, User, issue_session  # noqa: E402
from opswarden_api.config import get_settings  # noqa: E402


@pytest.fixture
def client():
    return TestClient(app, follow_redirects=False)


def _cookie(groups):
    return {SESSION_COOKIE: issue_session(User("tester", groups), get_settings())}


MUTATING = [
    ("/proposals/prop-abc/approve", {}),
    ("/proposals/prop-abc/reject", {}),
    ("/workflows/new-hire", {"username": "x", "role": "dba"}),
    ("/workflows/offboard", {"username": "x"}),
    ("/workflows/patch", {"check_only": "true"}),
]


@pytest.mark.parametrize("path,data", MUTATING)
def test_mutating_routes_reject_anonymous_callers(client, path, data):
    r = client.post(path, data=data)
    assert r.status_code == 401, f"{path} was reachable without a session ({r.status_code})"


def test_approve_rejects_a_signed_in_non_approver(client):
    r = client.post("/proposals/prop-abc/approve", cookies=_cookie(("developers",)))
    assert r.status_code == 403


def test_approver_passes_authorisation_then_fails_on_a_missing_proposal(client):
    """Proves the 403 above is authorisation, not a route that rejects everyone."""
    r = client.post("/proposals/prop-does-not-exist/approve", cookies=_cookie(("sysadmins",)))
    assert r.status_code == 404


def test_events_requires_the_ingest_token(client):
    body = {"kind": "ssh_brute_force", "host": "app-01"}
    assert client.post("/events", json=body).status_code == 401
    assert client.post("/events", json=body,
                       headers={"X-OpsWarden-Token": "wrong"}).status_code == 401


def test_read_routes_require_a_session(client):
    assert client.get("/allowlist").status_code == 401
    assert client.get("/proposals").status_code == 401


def test_health_and_login_stay_public(client):
    assert client.get("/healthz").status_code == 200
    assert client.get("/login").status_code == 200
