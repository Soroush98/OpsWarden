"""FastAPI app: receives events, drives the LangGraph flow, and serves the approval + audit UI.

The UI is the fallback approval channel (works with no Slack). Slack interactions resume the same
graph, so both paths are equivalent.
"""
from __future__ import annotations

import json
import logging
from contextlib import asynccontextmanager
from uuid import uuid4

from fastapi import BackgroundTasks, Depends, FastAPI, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from jinja2 import DictLoader, Environment
from langgraph.types import Command
from opswarden_core import PLAYBOOK_ALLOWLIST, Event, EventKind, ProposedAction, Severity

from opswarden_api import ticketing
from opswarden_api.auth import (
    SESSION_COOKIE,
    AuthError,
    User,
    authenticate,
    current_user,
    issue_session,
    require_approver,
    require_ingest_token,
    require_user,
)
from opswarden_api.config import get_settings
from opswarden_api.graph import build_graph
from opswarden_api.store import Store

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")

settings = get_settings()
store = Store(settings.db_path)
graph = build_graph(settings, store)

_TEMPLATES = {
"list.html": """<!doctype html><html><head><title>OpsWarden</title><meta charset=utf-8>
<style>body{font:14px system-ui;margin:2rem;color:#111;background:#fafafa}
h1{font-size:1.3rem}table{border-collapse:collapse;width:100%}
td,th{border:1px solid #ddd;padding:.5rem .6rem;text-align:left}
.s{font-weight:600;padding:.1rem .5rem;border-radius:.4rem;font-size:.8rem}
.awaiting_approval{background:#fff3cd}.executed{background:#d1e7dd}.rejected{background:#e2e3e5}
.failed{background:#f8d7da}a{color:#0d6efd;text-decoration:none}
.req{background:#fff;border:1px solid #ddd;border-radius:.5rem;padding:.8rem;margin:.8rem 0}
.req form{margin-top:.5rem}
button{padding:.3rem .8rem;border-radius:.3rem;border:1px solid #0d6efd;background:#0d6efd;color:#fff;cursor:pointer}
input,select{padding:.3rem;border:1px solid #ccc;border-radius:.3rem}
.del{border:1px solid #dc3545;background:#fff;color:#dc3545;border-radius:.3rem;cursor:pointer;padding:.2rem .5rem}
.del:hover{background:#dc3545;color:#fff}
.bar{display:flex;justify-content:space-between;align-items:center;background:#fff;
border:1px solid #ddd;border-radius:.5rem;padding:.6rem .9rem;margin-bottom:1rem}
.link{background:none;border:0;color:#0d6efd;cursor:pointer;padding:0 0 0 .6rem}
.executing{background:#cfe2ff}</style></head>
<body><div class=bar><b>🛡️ OpsWarden</b>
<span>signed in as <b>{{ user.username }}</b>{% if can_approve %} · approver{% else %} · read-only{% endif %}
<form method=post action="/logout" style="display:inline"><button class=link>sign out</button></form></span></div>
<h1>proposals &amp; audit</h1>
<div class=req><b>Raise a request</b> &nbsp;(each one opens a proposal that still needs approval)
<form method=post action="/workflows/new-hire" style="display:inline-block;margin-right:1rem">
  <input name=username placeholder="username" required size=10>
  <select name=role><option>dba</option><option>sysadmin</option><option>developer</option></select>
  <input name=full_name placeholder="Full Name" size=12>
  <button>New hire</button></form>
<form method=post action="/workflows/offboard" style="display:inline-block;margin-right:1rem">
  <input name=username placeholder="username" required size=10><button>Offboard</button></form>
<form method=post action="/workflows/patch" style="display:inline-block">
  <select name=check_only><option value="true">dry run</option><option value="false">apply updates</option></select>
  <button>Patch window</button></form>
</div>
<table><tr><th>Ticket</th><th>Status</th><th>Summary</th><th>When</th>{% if can_approve %}<th></th>{% endif %}</tr>
{% for p in proposals %}<tr><td><a href="/proposals/{{p.id}}">{{p.ticket_number or p.id}}</a></td>
<td><span class="s {{p.status}}">{{p.status}}</span></td><td>{{p.summary}}</td>
<td>{{p.created_at}}</td>{% if can_approve %}<td><form method=post action="/proposals/{{p.id}}/delete"
onsubmit="return confirm('Delete {{p.ticket_number or p.id}} and its ServiceNow incident?')"
style="margin:0"><button class=del title="delete proposal + ServiceNow incident">&#128465;</button></form></td>
{% endif %}</tr>{% endfor %}</table>
{% if not proposals %}<p>No proposals yet.</p>{% endif %}</body></html>""",

"detail.html": """<!doctype html><html><head><title>{{p.ticket_number}}</title><meta charset=utf-8>
<style>body{font:14px system-ui;margin:2rem;color:#111;background:#fafafa;max-width:900px}
h1{font-size:1.2rem}pre{background:#111;color:#eee;padding:.8rem;border-radius:.4rem;overflow:auto;font-size:12px}
.box{background:#fff;border:1px solid #ddd;border-radius:.5rem;padding:1rem;margin:.8rem 0}
.btn{display:inline-block;padding:.5rem 1.2rem;border-radius:.4rem;color:#fff;border:0;font-size:1rem;cursor:pointer}
.ok{background:#198754}.no{background:#dc3545}.s{font-weight:600;padding:.1rem .5rem;border-radius:.4rem}
.awaiting_approval{background:#fff3cd}.executed{background:#d1e7dd}.rejected{background:#e2e3e5}
.failed{background:#f8d7da}.executing{background:#cfe2ff}
li{margin:.2rem 0}</style></head><body>
<p><a href="/proposals">&larr; all proposals</a></p>
<h1>{{p.ticket_number or p.id}} &nbsp;<span class="s {{p.status}}">{{p.status}}</span>
{% if can_approve %}<form method=post action="/proposals/{{p.id}}/delete" style="display:inline;float:right"
onsubmit="return confirm('Delete {{p.ticket_number or p.id}} and its ServiceNow incident?')">
<button class="btn no">Delete</button></form>{% endif %}</h1>
<div class=box><b>Summary.</b> {{p.summary}}<br><br><b>Risk.</b> {{p.risk}}</div>
<div class=box><b>Detected event</b><ul>
<li>{{p.event.count}} failed logins from <b>{{p.event.source_ip}}</b> against
<b>{{p.event.target_user}}</b> on {{p.event.host}}</li>
<li>dormant: {{p.event.dormant_days if p.event.dormant_days is not none else 'never logged in'}}</li></ul>
<b>Recommended actions</b><ol>{% for a in p.actions %}<li>{{a.description}}
<code>({{a.playbook}} {{a.params}})</code></li>{% endfor %}</ol></div>
{% if p.status == 'awaiting_approval' %}
  {% if can_approve %}
<div class=box><form method=post action="/proposals/{{p.id}}/approve" style="display:inline">
<button class="btn ok">✅ Approve</button></form>
&nbsp;<form method=post action="/proposals/{{p.id}}/reject" style="display:inline">
<button class="btn no">Reject</button></form>
<div style="margin-top:.6rem;color:#666;font-size:.85rem">Approving as
<b>{{ user.username }}</b>; the audit trail records this verified identity.</div></div>
  {% else %}
<div class=box>Awaiting approval. Your account is not in the approver group, so you can view this
but not decide it.</div>
  {% endif %}
{% endif %}
{% if p.status == 'executing' %}<div class=box>⏳ Executing. Refresh for the result.</div>{% endif %}
{% if p.get('postcheck') %}<div class=box><b>Post-check.</b>
failed logins from {{p.postcheck.source_ip}} in last 5m: <b>{{p.postcheck.failed_last_5m}}</b></div>{% endif %}
{% for r in p.get('results', []) %}<div class=box><b>Evidence — {{r.playbook}} {{r.params}}</b>
(rc={{r.rc}})<pre>{{r.stdout[-4000:]}}</pre></div>{% endfor %}
<div class=box><b>Audit trail</b><ul>{% for e in p.get('audit', []) %}
<li>{{e.at}} — {{e.entry}}</li>{% endfor %}</ul></div></body></html>""",
}
_env = Environment(loader=DictLoader(_TEMPLATES), autoescape=True)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logging.getLogger("opswarden").info("OpsWarden agent ready at %s", settings.base_url)
    yield


app = FastAPI(title="OpsWarden Agent", lifespan=lifespan)


LOGIN_HTML = """<!doctype html><html><head><title>OpsWarden sign in</title><meta charset=utf-8>
<style>body{font:14px system-ui;margin:0;height:100vh;display:flex;align-items:center;
justify-content:center;background:#f4f5f7;color:#111}
.card{background:#fff;border:1px solid #ddd;border-radius:.6rem;padding:2rem;min-width:320px}
h1{font-size:1.1rem;margin:0 0 1rem}label{display:block;margin:.6rem 0 .2rem;font-size:.85rem}
input{width:100%;padding:.5rem;border:1px solid #ccc;border-radius:.3rem;box-sizing:border-box}
button{margin-top:1rem;width:100%;padding:.55rem;border:0;border-radius:.35rem;background:#0d6efd;
color:#fff;font-size:1rem;cursor:pointer}.err{color:#b02a37;font-size:.85rem;margin-top:.6rem}
.hint{color:#666;font-size:.8rem;margin-top:.8rem}</style></head><body>
<form class=card method=post action="/login"><h1>🛡️ OpsWarden</h1>
<label>Directory username</label><input name=username autofocus required>
<label>Password</label><input name=password type=password required>
<button>Sign in</button>__ERR__
<div class=hint>Authenticates against LDAP. Approving requires the sysadmins group.</div>
</form></body></html>"""


@app.get("/login", response_class=HTMLResponse)
def login_form(error: str = ""):
    err = f'<div class="err">{error}</div>' if error else ""
    return LOGIN_HTML.replace("__ERR__", err)


@app.post("/login")
def login(username: str = Form(...), password: str = Form(...), s=Depends(get_settings)):
    try:
        user = authenticate(username, password, s)
    except AuthError:
        # Deliberately vague: never reveal whether the account exists.
        return RedirectResponse("/login?error=Invalid+credentials", status_code=303)
    resp = RedirectResponse("/proposals", status_code=303)
    resp.set_cookie(SESSION_COOKIE, issue_session(user, s), httponly=True, samesite="lax",
                    max_age=s.session_max_age, secure=s.cookie_secure)
    logging.getLogger("opswarden.auth").info("sign-in: %s (groups=%s)", user.username, user.groups)
    return resp


@app.post("/logout")
def logout():
    resp = RedirectResponse("/login", status_code=303)
    resp.delete_cookie(SESSION_COOKIE)
    return resp


@app.exception_handler(HTTPException)
async def _auth_redirect(request: Request, exc: HTTPException):
    """Browsers get a login page; API clients get the structured error."""
    wants_html = "text/html" in request.headers.get("accept", "")
    if exc.status_code == status.HTTP_401_UNAUTHORIZED and wants_html:
        return RedirectResponse("/login", status_code=303)
    return JSONResponse({"error": exc.detail}, status_code=exc.status_code)


@app.get("/healthz")
def healthz():
    return {"ok": True}


@app.post("/events", dependencies=[Depends(require_ingest_token)])
def ingest_event(event: Event):
    """Machine ingress for the detector. Authenticated by a shared token; can never approve."""
    return _start(event)


def _resume(pid: str, decision: str, approver: str):
    cfg = {"configurable": {"thread_id": pid}}
    graph.invoke(Command(resume={"decision": decision, "approver": approver}), cfg)


def _resume_guarded(pid: str, decision: str, approver: str) -> None:
    """Background execution must never fail silently.

    Without this, an exception inside the graph left the proposal displaying "executing"
    for ever, with no error anywhere the operator could see.
    """
    try:
        _resume(pid, decision, approver)
    except Exception as exc:  # noqa: BLE001
        logging.getLogger("opswarden").exception("execution failed for %s", pid)
        store.set_status(pid, "failed")
        store.append_audit(pid, f"Execution failed: {type(exc).__name__}: {exc}"[:500])


def _start(event: Event) -> dict:
    """Open a proposal, unless one for the same situation is already awaiting a decision.

    The detector re-reports an ongoing attack on every scan; without this a single brute force
    produced a new proposal and a new ticket every couple of minutes.
    """
    key = event.dedup_key()
    existing = store.find_open_duplicate(key, settings.dedup_window_minutes)
    if existing:
        store.append_audit(existing["id"], f"Duplicate detection suppressed ({event.id})")
        return {"proposal_id": existing["id"], "ticket": existing.get("ticket_number"),
                "status": existing.get("status"), "deduplicated": True}

    pid = f"prop-{uuid4().hex[:12]}"
    cfg = {"configurable": {"thread_id": pid}}
    graph.invoke({"event": event.model_dump(mode="json"), "proposal_id": pid}, cfg)
    doc = store.get(pid)
    if doc is not None:
        doc["dedup_key"] = key
        store.upsert(doc)
    doc = doc or {}
    return {"proposal_id": pid, "ticket": doc.get("ticket_number"),
            "status": doc.get("status"), "deduplicated": False}


@app.post("/workflows/new-hire")
def workflow_new_hire(username: str = Form(...), role: str = Form(...),
                      full_name: str = Form(default=""),
                      user: User = Depends(require_user)):
    """Service request: onboard a new hire (joiner) through the same approval gate."""
    ev = Event(kind=EventKind.new_hire, severity=Severity.low, host="app-01",
               payload={"username": username, "role": role, "full_name": full_name or username})
    _start(ev)
    return RedirectResponse("/proposals", status_code=303)


@app.post("/workflows/offboard")
def workflow_offboard(username: str = Form(...), user: User = Depends(require_user)):
    """Service request: disable a leaver and flag orphaned SSH keys."""
    ev = Event(kind=EventKind.offboarding, severity=Severity.medium, host="app-01",
               payload={"username": username})
    _start(ev)
    return RedirectResponse("/proposals", status_code=303)


@app.post("/workflows/patch")
def workflow_patch(check_only: str = Form(default="true"),
                   user: User = Depends(require_user)):
    """Change request: patch validation with pre/post evidence."""
    ev = Event(kind=EventKind.patch_window, severity=Severity.low, host="app-01",
               payload={"check_only": check_only})
    _start(ev)
    return RedirectResponse("/proposals", status_code=303)


@app.post("/actions/validate")
def validate_action(playbook: str = Form(...), params: str = Form(default="{}"),
                    user: User = Depends(require_user)):
    """Guardrail check: would this action be allowed? Used to demonstrate that the agent cannot
    invoke anything outside the allowlist, whatever it proposes."""
    try:
        parsed = json.loads(params or "{}")
    except json.JSONDecodeError as exc:
        return JSONResponse({"allowed": False, "reason": f"params is not valid JSON: {exc}"}, 400)
    try:
        action = ProposedAction(playbook=playbook, params=parsed, description="validation probe")
        action.validate_against_allowlist()
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"allowed": False, "playbook": playbook, "reason": str(exc)}, 200)
    return JSONResponse({"allowed": True, "playbook": playbook}, 200)


@app.get("/allowlist")
def allowlist(user: User = Depends(require_user)):
    """The complete set of playbooks and parameters the agent may ever use."""
    return {k: sorted(v) for k, v in PLAYBOOK_ALLOWLIST.items()}


def _require_pending(pid: str) -> dict:
    doc = store.get(pid)
    if doc is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND,
                            detail={"code": "no_such_proposal", "message": "unknown proposal"})
    if doc.get("status") != "awaiting_approval":
        raise HTTPException(status.HTTP_409_CONFLICT,
                            detail={"code": "not_pending",
                                    "message": f"proposal is {doc.get('status')}"})
    return doc


@app.post("/proposals/{pid}/approve")
def approve(pid: str, background: BackgroundTasks, user: User = Depends(require_approver)):
    """The approver is the authenticated directory user, never a value the caller supplies."""
    _require_pending(pid)
    # Playbooks can run for many minutes (a full dnf update took ~17), so execute after the
    # response: the approval request returns at once and cannot time out mid-change.
    store.set_status(pid, "executing")
    store.append_audit(pid, f"Approved by {user.username}; execution queued")
    background.add_task(_resume_guarded, pid, "approve", user.username)
    return RedirectResponse(f"/proposals/{pid}", status_code=303)


@app.post("/proposals/{pid}/reject")
def reject(pid: str, user: User = Depends(require_approver)):
    _require_pending(pid)
    _resume(pid, "reject", user.username)
    return RedirectResponse(f"/proposals/{pid}", status_code=303)


@app.post("/proposals/{pid}/delete")
def delete_proposal(pid: str, user: User = Depends(require_approver)):
    """Remove a proposal from the agent and delete its ServiceNow incident.

    Destructive, so restricted to approvers. A local-only ticket has no ServiceNow side.
    """
    from opswarden_core import Ticket

    doc = store.get(pid)
    if doc is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND,
                            detail={"code": "no_such_proposal", "message": "unknown proposal"})
    snow_ok = True
    if doc.get("ticket"):
        snow_ok = ticketing.delete_incident(Ticket.model_validate(doc["ticket"]), settings)
    store.delete(pid)
    logging.getLogger("opswarden").info(
        "proposal %s (ticket %s) deleted by %s; servicenow_deleted=%s",
        pid, doc.get("ticket_number"), user.username, snow_ok)
    return RedirectResponse("/proposals", status_code=303)


@app.get("/")
def index(user: User | None = Depends(current_user)):
    return RedirectResponse("/proposals" if user else "/login", status_code=303)


@app.get("/proposals", response_class=HTMLResponse)
def list_proposals(user: User = Depends(require_user), s=Depends(get_settings)):
    return _env.get_template("list.html").render(
        proposals=store.list(), user=user, can_approve=user.in_group(s.approver_group))


@app.get("/proposals/{pid}", response_class=HTMLResponse)
def proposal_detail(pid: str, user: User = Depends(require_user), s=Depends(get_settings)):
    doc = store.get(pid)
    if not doc:
        raise HTTPException(status.HTTP_404_NOT_FOUND,
                            detail={"code": "no_such_proposal", "message": "unknown proposal"})
    return _env.get_template("detail.html").render(
        p=doc, user=user, can_approve=user.in_group(s.approver_group))


@app.post("/slack/interactions")
async def slack_interactions(request: Request, s=Depends(get_settings)):
    # Slack payloads are unauthenticated until the signing secret is verified.
    if not s.slack_signing_secret:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE,
                            detail={"code": "slack_disabled",
                                    "message": "no Slack signing secret configured"})
    form = await request.form()
    payload = json.loads(form.get("payload", "{}"))
    action = (payload.get("actions") or [{}])[0]
    value = action.get("value", "")   # "approve:<pid>" / "reject:<pid>"
    user = payload.get("user", {}).get("username", "slack-user")
    if ":" in value:
        decision, pid = value.split(":", 1)
        _resume(pid, decision, user)
        return JSONResponse({"text": f"{decision} recorded for {pid} by {user}"})
    return JSONResponse({"text": "no action"})


def run():
    import uvicorn
    uvicorn.run("opswarden_api.app:app", host="0.0.0.0", port=8080, log_level="info")
