"""Approval notifications. Posts to Slack when configured; always logs. The built-in web UI is
the fallback approval channel, so the agent is fully usable without Slack."""
from __future__ import annotations

import logging

import httpx
from opswarden_core import Proposal

from opswarden_api.config import Settings

log = logging.getLogger("opswarden.notify")


def announce_proposal(proposal: Proposal, s: Settings) -> None:
    url = f"{s.base_url}/proposals/{proposal.id}"
    text = (f":rotating_light: *{proposal.summary}*\n"
            f"Recommended: " + "; ".join(a.description for a in proposal.actions) +
            f"\nApprove or reject: {url}")
    log.info("PROPOSAL %s ticket=%s -> %s", proposal.id, proposal.ticket_number, url)
    if s.slack_webhook_url:
        try:
            httpx.post(s.slack_webhook_url, json={"text": text}, timeout=10).raise_for_status()
        except Exception as exc:  # noqa: BLE001
            log.warning("slack post failed: %s", exc)


def announce_result(proposal: Proposal, ok: bool, s: Settings) -> None:
    msg = f"{'✅' if ok else '❌'} {proposal.id} ({proposal.ticket_number}) execution {'succeeded' if ok else 'FAILED'}"
    log.info(msg)
    if s.slack_webhook_url:
        try:
            httpx.post(s.slack_webhook_url, json={"text": msg}, timeout=10)
        except Exception:  # noqa: BLE001
            pass
