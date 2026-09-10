"""Deterministic action policy. The authoritative source of *what* may be done in response to an
event; the LLM only writes the human-readable rationale. Every action is validated against the
allowlist before it can be shown to a human or executed."""
from __future__ import annotations

import re

from opswarden_core import Event, EventKind, ProposedAction

USERNAME_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
ROLE_CATALOG = {"dba", "sysadmin", "developer"}


def _require_username(event: Event) -> str:
    user = event.payload.get("username", "").strip()
    if not USERNAME_RE.match(user):
        raise ValueError(f"invalid username {user!r}")
    return user


def propose_actions(event: Event, run_id: str) -> list[ProposedAction]:
    actions: list[ProposedAction] = []

    if event.kind == EventKind.ssh_brute_force:
        if event.target_user:
            actions.append(ProposedAction(
                playbook="remediate.yml",
                params={"remediate_action": "lock_account",
                        "remediate_username": event.target_user,
                        "remediate_run_id": run_id},
                description=f"Lock account '{event.target_user}' in LDAP (bind will be rejected)."))
        if event.source_ip:
            actions.append(ProposedAction(
                playbook="remediate.yml",
                params={"remediate_action": "block_ip",
                        "remediate_ip": event.source_ip,
                        "remediate_run_id": run_id},
                description=f"Block {event.source_ip} with firewalld on the app servers."))

    elif event.kind == EventKind.new_hire:
        user = _require_username(event)
        role = event.payload.get("role", "")
        if role not in ROLE_CATALOG:
            raise ValueError(f"role {role!r} is not in the catalog {sorted(ROLE_CATALOG)}")
        full = event.payload.get("full_name") or user
        given = event.payload.get("given_name") or full.split(" ")[0]
        sn = event.payload.get("sn") or (full.split(" ")[-1] if " " in full else user)
        actions.append(ProposedAction(
            playbook="jml.yml",
            params={"jml_action": "joiner", "jml_username": user, "jml_role": role,
                    "jml_full_name": full, "jml_given_name": given, "jml_sn": sn,
                    "jml_run_id": run_id},
            description=(f"Create LDAP account '{user}' for role '{role}', add group membership, "
                         f"and verify login on both app servers.")))

    elif event.kind == EventKind.offboarding:
        user = _require_username(event)
        actions.append(ProposedAction(
            playbook="jml.yml",
            params={"jml_action": "leaver", "jml_username": user, "jml_run_id": run_id},
            description=(f"Disable LDAP account '{user}', strip group membership, and report any "
                         f"orphaned SSH keys on the app servers.")))

    elif event.kind == EventKind.patch_window:
        check_only = str(event.payload.get("check_only", "true")).lower() in ("1", "true", "yes")
        actions.append(ProposedAction(
            playbook="patch.yml",
            params={"patch_check_only": check_only, "patch_run_id": run_id},
            description=("Snapshot services, packages, ports, disk and logs; "
                         + ("list available updates only (no changes)" if check_only
                            else "run dnf update")
                         + "; re-snapshot and diff, attaching the raw output as evidence.")))

    else:
        raise ValueError(f"no policy for event kind {event.kind}")

    for a in actions:
        a.validate_against_allowlist()
    return actions
