"""Ticketing. Creates a ServiceNow incident when a PDI is configured; otherwise mints a local
ticket number and keeps the evidence in the agent's own store."""
from __future__ import annotations

import logging
import time
import uuid

import httpx
from opswarden_core import Proposal, Ticket

from opswarden_api.config import Settings

log = logging.getLogger("opswarden.ticket")
# (access_token, expiry_epoch). ServiceNow tokens live ~30 min; a stale one gives 401 on every
# call, so cache with an expiry and a safety margin, and refresh on demand.
_token: tuple[str, float] | None = None


def _base(s: Settings) -> str:
    return f"https://{s.servicenow_instance}.service-now.com"


def _uses_oauth(s: Settings) -> bool:
    return bool(s.servicenow_client_id and s.servicenow_client_secret)


def _fetch_token(s: Settings) -> str:
    global _token
    r = httpx.post(f"{_base(s)}/oauth_token.do", data={
        "grant_type": "password",
        "client_id": s.servicenow_client_id,
        "client_secret": s.servicenow_client_secret,
        "username": s.servicenow_user,
        "password": s.servicenow_password or "",
        # Without an explicit scope the instance issues an empty-scope token and refuses every
        # unscoped platform API (403 "Access to unscoped api is not allowed").
        "scope": s.servicenow_scope},
        timeout=20)
    r.raise_for_status()
    body = r.json()
    ttl = int(body.get("expires_in", 1800))
    _token = (body["access_token"], time.monotonic() + ttl - 120)  # 2-min safety margin
    return _token[0]


def _auth_kwargs(s: Settings, force_refresh: bool = False) -> dict:
    """Bearer token (OAuth password grant) when client credentials are set, else basic auth.
    The token is refreshed when it is missing, near expiry, or a caller forces it after a 401."""
    if not _uses_oauth(s):
        return {"auth": (s.servicenow_user, s.servicenow_password or ""),
                "headers": {"Accept": "application/json"}}
    tok = None if force_refresh else (_token[0] if _token and time.monotonic() < _token[1] else None)
    if tok is None:
        tok = _fetch_token(s)
    return {"headers": {"Authorization": f"Bearer {tok}", "Accept": "application/json"}}


def _request(method: str, url: str, s: Settings, **kw) -> httpx.Response:
    """One ServiceNow call, retried once with a fresh token if the first attempt is a 401."""
    r = httpx.request(method, url, **_auth_kwargs(s), timeout=20, **kw)
    if r.status_code == 401 and _uses_oauth(s):
        r = httpx.request(method, url, **_auth_kwargs(s, force_refresh=True), timeout=20, **kw)
    return r


def update_fields(ticket: Ticket, fields: dict, s: Settings) -> None:
    """Patch arbitrary fields on the incident (used to fill in the narrative once written)."""
    if s.servicenow_instance and ticket.sys_id:
        try:
            _request("PATCH", f"{_base(s)}/api/now/table/incident/{ticket.sys_id}", s, json=fields)
        except Exception as exc:  # noqa: BLE001
            log.warning("ServiceNow field update failed: %s", exc)


def open_incident(proposal: Proposal, s: Settings, title: str = "") -> Ticket:
    if s.servicenow_instance and s.servicenow_user:
        base = _base(s)
        try:
            r = _request("POST", f"{base}/api/now/table/incident", s,
                         json={"short_description": title or proposal.summary or "OpsWarden request",
                               "description": proposal.risk,
                               "urgency": "1", "impact": "2"})
            r.raise_for_status()
            res = r.json()["result"]
            num = res["number"]
            return Ticket(number=num, sys_id=res["sys_id"],
                          url=f"{base}/nav_to.do?uri=incident.do?sys_id={res['sys_id']}")
        except Exception as exc:  # noqa: BLE001
            log.warning("ServiceNow create failed (%s); using local ticket", exc)
    # Local fallback only. A process-local counter restarted at 10001 on every pod restart and
    # produced colliding "incident numbers"; a random id can never collide and is obviously local.
    return Ticket(number=f"LOCAL-{uuid.uuid4().hex[:8].upper()}",
                  url=f"{s.base_url}/proposals/{proposal.id}")


def add_work_note(ticket: Ticket, note: str, s: Settings) -> None:
    if s.servicenow_instance and ticket.sys_id:
        try:
            _request("PATCH", f"{_base(s)}/api/now/table/incident/{ticket.sys_id}", s,
                     json={"work_notes": note})
        except Exception as exc:  # noqa: BLE001
            log.warning("ServiceNow work note failed: %s", exc)


def delete_incident(ticket: Ticket, s: Settings) -> bool:
    """Delete the incident from ServiceNow. Returns True if deleted or nothing to delete."""
    if not (s.servicenow_instance and ticket.sys_id):
        return True  # local-only ticket; nothing on the ServiceNow side
    try:
        r = _request("DELETE", f"{_base(s)}/api/now/table/incident/{ticket.sys_id}", s)
        if r.status_code in (200, 204):
            return True
        log.warning("ServiceNow delete rejected (%s): %s", r.status_code, r.text[:300])
        return False
    except Exception as exc:  # noqa: BLE001
        log.warning("ServiceNow delete failed: %s", exc)
        return False


def resolve(ticket: Ticket, note: str, s: Settings) -> None:
    """Move the incident to Resolved. ServiceNow rejects state=6 without a close code
    (403), so send close_code and close_notes together with the state."""
    if s.servicenow_instance and ticket.sys_id:
        try:
            r = _request("PATCH", f"{_base(s)}/api/now/table/incident/{ticket.sys_id}", s,
                         json={"state": "6",
                               "close_code": s.servicenow_close_code,
                               "close_notes": note})
            if r.status_code >= 300:
                log.warning("ServiceNow resolve rejected (%s): %s", r.status_code, r.text[:300])
        except Exception as exc:  # noqa: BLE001
            log.warning("ServiceNow resolve failed: %s", exc)
