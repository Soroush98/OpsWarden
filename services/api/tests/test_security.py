"""Security-relevant behaviour that must not regress."""
import json

import pytest
from fastapi import HTTPException
from opswarden_api.auth import User, issue_session, read_session, require_approver
from opswarden_api.config import Settings
from opswarden_api.llm import _bounded_payload, _parse_narrative
from opswarden_core import Event, EventKind, ProposedAction


def _settings(**kw) -> Settings:
    return Settings(session_secret="test-secret-not-a-real-one", **kw)


# --- sessions -------------------------------------------------------------
def test_session_roundtrip_preserves_identity_and_groups():
    s = _settings()
    tok = issue_session(User("soroosh", ("sysadmins",)), s)
    back = read_session(tok, s)
    assert back.username == "soroosh"
    assert back.in_group("sysadmins")


def test_tampered_session_is_rejected():
    s = _settings()
    tok = issue_session(User("nobody", ()), s)
    assert read_session(tok[:-3] + "aaa", s) is None


def test_session_signed_with_another_secret_is_rejected():
    tok = issue_session(User("soroosh", ("sysadmins",)), _settings())
    assert read_session(tok, Settings(session_secret="a-different-secret")) is None


# --- authorisation --------------------------------------------------------
def test_non_member_cannot_approve():
    s = _settings()
    with pytest.raises(HTTPException) as exc:
        require_approver(User("intern", ("developers",)), s)
    assert exc.value.status_code == 403


def test_member_can_approve():
    s = _settings()
    assert require_approver(User("soroosh", ("sysadmins",)), s).username == "soroosh"


# --- model output is untrusted --------------------------------------------
@pytest.mark.parametrize("bad", [
    "I will not comply",
    "{}",
    '{"summary": ""}',
    "",
    '{"nope": 1}',
])
def test_malformed_model_output_is_rejected(bad):
    assert _parse_narrative(bad) is None


def test_valid_model_output_is_accepted():
    assert _parse_narrative('{"summary":"a summary","risk":"a risk"}') == ("a summary", "a risk")


def test_untrusted_log_context_is_capped():
    ev = Event(kind=EventKind.ssh_brute_force, host="app-01", source_ip="10.0.0.9",
               target_user="svc-backup", raw_context=["x" * 5000] * 200)
    payload = json.loads(_bounded_payload(ev, []))
    assert len(payload["event"]["raw_context"]) <= 10
    assert all(len(line) <= 300 for line in payload["event"]["raw_context"])


def test_dedup_key_is_stable_for_the_same_situation():
    kw = dict(kind=EventKind.ssh_brute_force, host="app-01",
              source_ip="10.0.0.9", target_user="svc-backup")
    assert Event(**kw, count=12).dedup_key() == Event(**kw, count=99).dedup_key()
    assert Event(**kw).dedup_key() != Event(**{**kw, "source_ip": "10.0.0.8"}).dedup_key()


def test_allowlist_still_refuses_unknown_playbooks():
    with pytest.raises(ValueError):
        ProposedAction(playbook="rm-rf.yml", params={}, description="no")


# --- regression: the graph must only read settings that exist ---
def test_graph_does_not_reference_missing_settings():
    """A removed setting once left approvals hanging in 'executing' for ever."""
    import re
    from pathlib import Path

    src = Path(__file__).resolve().parents[1] / "opswarden_api" / "graph.py"
    referenced = set(re.findall(r"\bs\.([a-z_]+)", src.read_text()))
    known = set(Settings.model_fields)
    assert referenced <= known, f"graph.py reads settings that do not exist: {referenced - known}"


# --- regression: ServiceNow token must refresh, not go stale ---
def test_servicenow_token_refreshes_on_401(monkeypatch):
    """A cached token that outlived its 30-min lifespan once made every incident fall back to
    a local ticket. A 401 must trigger one refresh-and-retry."""
    import opswarden_api.ticketing as t

    s = Settings(servicenow_instance="dev", servicenow_user="admin",
                 servicenow_password="pw", servicenow_client_id="cid",
                 servicenow_client_secret="csec")

    tokens = iter(["stale-token", "fresh-token"])
    monkeypatch.setattr(t, "_fetch_token", lambda _s: next(tokens))
    t._token = None

    calls = []

    class Resp:
        def __init__(self, code): self.status_code = code

    def fake_request(method, url, headers=None, **kw):
        calls.append(headers["Authorization"])
        # first call (stale token) is rejected; retry with the fresh token succeeds
        return Resp(401) if headers["Authorization"].endswith("stale-token") else Resp(201)

    monkeypatch.setattr(t.httpx, "request", fake_request)
    r = t._request("POST", "https://dev.service-now.com/api/now/table/incident", s, json={})
    assert r.status_code == 201
    assert calls == ["Bearer stale-token", "Bearer fresh-token"]
