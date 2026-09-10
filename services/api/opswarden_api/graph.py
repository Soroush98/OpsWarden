"""The agent flow as a LangGraph state machine:

  propose (policy + LLM narrative, open ticket)  ->  await_approval (INTERRUPT)
     -> [approve] execute playbooks -> post-check -> resolve ticket
     -> [reject]  record and close

The approval is a real interrupt: the graph pauses with durable state in the SQLite checkpointer
and only resumes when a human approves/rejects via the UI or Slack — hours later if need be.
"""
from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from typing import TypedDict

from langgraph.checkpoint.sqlite import SqliteSaver
from langgraph.graph import END, START, StateGraph
from langgraph.types import interrupt
from opswarden_core import Event, EventKind, Proposal, ProposalStatus

from opswarden_api import llm, notify, policy, runner, ticketing
from opswarden_api.config import Settings
from opswarden_api.estools import ESReader
from opswarden_api.store import Store


class GState(TypedDict, total=False):
    event: dict
    proposal_id: str
    proposal: dict
    decision: dict
    status: str


def _event_title(event: Event) -> str:
    """A short, deterministic incident title (independent of the LLM)."""
    k = event.kind
    if k == EventKind.ssh_brute_force:
        return (f"SSH brute force from {event.source_ip} against "
                f"{event.target_user} on {event.host}")
    if k == EventKind.new_hire:
        return f"Onboard {event.payload.get('username', '?')} ({event.payload.get('role', '?')})"
    if k == EventKind.offboarding:
        return f"Offboard {event.payload.get('username', '?')}"
    if k == EventKind.patch_window:
        dry = str(event.payload.get("check_only", "true")).lower() in ("1", "true", "yes")
        return f"Patch window ({'dry run' if dry else 'apply updates'}) - app servers"
    return f"{k} on {event.host}"


def build_graph(s: Settings, store: Store):
    def propose(state: GState) -> dict:
        event = Event.model_validate(state["event"])
        pid = state["proposal_id"]
        proposal = Proposal(id=pid, event=event, summary="", actions=[])
        # Open the ticket with a deterministic one-line title so the incident is never blank,
        # then fill in the narrative below once it has been written.
        ticket = ticketing.open_incident(proposal, s, title=_event_title(event))
        proposal.ticket_number = ticket.number
        proposal.actions = policy.propose_actions(event, run_id=ticket.number)
        proposal.summary, proposal.risk = llm.narrate(event, proposal.actions, s)
        proposal.status = ProposalStatus.awaiting_approval
        doc = proposal.model_dump(mode="json")
        doc["ticket"] = ticket.model_dump(mode="json")
        doc["results"] = []
        store.upsert(doc)
        store.append_audit(pid, f"Proposal drafted; ticket {ticket.number} opened; awaiting approval")
        ticketing.update_fields(ticket, {"description": f"{proposal.summary}\n\nRisk: {proposal.risk}"}, s)
        ticketing.add_work_note(ticket, f"OpsWarden proposal:\n{proposal.summary}\n\nRisk: {proposal.risk}", s)
        notify.announce_proposal(proposal, s)
        return {"proposal": doc, "status": "awaiting_approval"}

    def await_approval(state: GState) -> dict:
        decision = interrupt({"proposal_id": state["proposal_id"],
                              "summary": state["proposal"]["summary"]})
        return {"decision": decision}

    def route(state: GState) -> str:
        return "execute" if state.get("decision", {}).get("decision") == "approve" else "reject"

    def execute(state: GState) -> dict:
        pid = state["proposal_id"]
        doc = store.get(pid)
        approver = state["decision"].get("approver", "unknown")
        store.append_audit(pid, f"Approved by {approver}; executing {len(doc['actions'])} action(s)")
        ticket = None
        from opswarden_core import Ticket
        if doc.get("ticket"):
            ticket = Ticket.model_validate(doc["ticket"])
        all_ok = True
        from opswarden_core import ProposedAction
        for a in doc["actions"]:
            action = ProposedAction.model_validate(a)
            res = runner.run_action(action, s)
            all_ok = all_ok and res.ok
            doc["results"].append(res.model_dump(mode="json"))
            store.upsert(doc)
            store.append_audit(pid, f"Ran {action.playbook} ({action.params.get('remediate_action','')}) rc={res.rc}")
            if ticket:
                ticketing.add_work_note(
                    ticket, f"Executed: {action.description}\nrc={res.rc}\n\n{res.stdout[-1500:]}", s)
        # Post-check via read-only ES: failed logins from the source IP should stop climbing.
        # This is evidence, not a gate. If the log store is unreachable the remediation still
        # happened, so record that the check was unavailable rather than failing a completed run.
        ev = Event.model_validate(doc["event"])
        if ev.source_ip:
            es = None
            try:
                es = ESReader(s)
                doc["postcheck"] = {"source_ip": ev.source_ip,
                                    "failed_last_5m": es.failed_count(ev.source_ip, minutes=5)}
            except Exception as exc:  # noqa: BLE001
                doc["postcheck"] = {"source_ip": ev.source_ip,
                                    "unavailable": f"{type(exc).__name__}"}
                store.append_audit(pid, f"Post-check unavailable: {type(exc).__name__}")
            finally:
                if es is not None:
                    es.close()
        doc["status"] = ProposalStatus.executed.value if all_ok else ProposalStatus.failed.value
        doc["executed_at"] = datetime.now(UTC).isoformat()
        doc["approver"] = approver
        store.upsert(doc)
        store.append_audit(pid, f"Execution {'succeeded' if all_ok else 'FAILED'}")
        if ticket:
            ticketing.resolve(ticket, "Remediation executed by OpsWarden after human approval.", s)
        proposal = Proposal.model_validate({k: v for k, v in doc.items() if k in Proposal.model_fields})
        notify.announce_result(proposal, all_ok, s)
        return {"status": doc["status"]}

    def reject(state: GState) -> dict:
        pid = state["proposal_id"]
        doc = store.get(pid)
        approver = state.get("decision", {}).get("approver", "unknown")
        doc["status"] = ProposalStatus.rejected.value
        doc["approver"] = approver
        store.upsert(doc)
        store.append_audit(pid, f"Rejected by {approver}")
        return {"status": "rejected"}

    g = StateGraph(GState)
    g.add_node("propose", propose)
    g.add_node("await_approval", await_approval)
    g.add_node("execute", execute)
    g.add_node("reject", reject)
    g.add_edge(START, "propose")
    g.add_edge("propose", "await_approval")
    g.add_conditional_edges("await_approval", route, {"execute": "execute", "reject": "reject"})
    g.add_edge("execute", END)
    g.add_edge("reject", END)

    conn = sqlite3.connect(s.db_path, check_same_thread=False)
    checkpointer = SqliteSaver(conn)
    return g.compile(checkpointer=checkpointer)
