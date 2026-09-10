"""Domain models shared across the detector, agent, and runner.

These are the contract between components. The agent may only ever propose a ProposedAction
whose `playbook` is in the allowlist and whose `params` validate — the guardrail that keeps a
language model from running arbitrary automation.
"""
from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator


def _now() -> datetime:
    return datetime.now(UTC)


class Severity(StrEnum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class EventKind(StrEnum):
    # security
    ssh_brute_force = "ssh_brute_force"
    off_hours_sudo = "off_hours_sudo"
    dormant_account_login = "dormant_account_login"
    # service-request workflows (ticket driven)
    new_hire = "new_hire"
    offboarding = "offboarding"
    patch_window = "patch_window"


class ProposalStatus(StrEnum):
    draft = "draft"
    awaiting_approval = "awaiting_approval"
    approved = "approved"
    rejected = "rejected"
    executed = "executed"
    failed = "failed"


# The ONLY playbooks the agent may invoke, and the parameters each accepts. The API validates
# every proposed action against this map before it is ever shown to a human or executed.
PLAYBOOK_ALLOWLIST: dict[str, set[str]] = {
    "remediate.yml": {"remediate_action", "remediate_username", "remediate_ip", "remediate_run_id"},
    "jml.yml": {"jml_action", "jml_username", "jml_role", "jml_full_name",
                "jml_given_name", "jml_sn", "jml_run_id"},
    "patch.yml": {"patch_check_only", "patch_run_id"},
}

# Within remediate.yml, the discrete actions the agent may request.
REMEDIATE_ACTIONS = {"lock_account", "unlock_account", "block_ip", "unblock_ip"}

# Within jml.yml, the discrete actions the agent may request.
JML_ACTIONS = {"joiner", "mover", "leaver"}


class Event(BaseModel):
    """Something worth a human's attention, emitted by the detector."""
    id: str = Field(default_factory=lambda: f"evt-{uuid4().hex[:12]}")
    kind: EventKind
    severity: Severity = Severity.high
    host: str
    target_user: str | None = None
    source_ip: str | None = None
    count: int = 0
    window_minutes: int = 5
    dormant_days: int | None = None
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    raw_context: list[str] = Field(default_factory=list)
    # Workflow-specific fields (e.g. username/role for a new hire, check_only for a patch run).
    payload: dict[str, str] = Field(default_factory=dict)
    detected_at: datetime = Field(default_factory=_now)

    def dedup_key(self) -> str:
        """Identifies the same real-world situation across repeated detections."""
        parts = [self.kind.value, self.host, self.target_user or "", self.source_ip or "",
                 self.payload.get("username", "")]
        return "|".join(parts)


class ProposedAction(BaseModel):
    playbook: str
    params: dict[str, str | bool]
    description: str

    @field_validator("playbook")
    @classmethod
    def _known_playbook(cls, v: str) -> str:
        if v not in PLAYBOOK_ALLOWLIST:
            raise ValueError(f"playbook {v!r} is not in the allowlist")
        return v

    def validate_against_allowlist(self) -> None:
        allowed = PLAYBOOK_ALLOWLIST[self.playbook]
        extra = set(self.params) - allowed
        if extra:
            raise ValueError(f"{self.playbook}: params not allowed: {sorted(extra)}")
        # Values are passed to ansible as separate argv entries (no shell), but reject control
        # characters outright so nothing can smuggle a second -e or a newline into a playbook.
        for k, v in self.params.items():
            if isinstance(v, str) and any(c in v for c in "\n\r\x00"):
                raise ValueError(f"{self.playbook}: parameter {k} contains control characters")
        if self.playbook == "remediate.yml":
            action = self.params.get("remediate_action")
            if action not in REMEDIATE_ACTIONS:
                raise ValueError(f"remediate_action {action!r} not allowed")
        if self.playbook == "jml.yml":
            action = self.params.get("jml_action")
            if action not in JML_ACTIONS:
                raise ValueError(f"jml_action {action!r} not allowed")


class Proposal(BaseModel):
    id: str = Field(default_factory=lambda: f"prop-{uuid4().hex[:12]}")
    event: Event
    summary: str
    actions: list[ProposedAction]
    risk: str = ""
    status: ProposalStatus = ProposalStatus.draft
    ticket_number: str | None = None
    created_at: datetime = Field(default_factory=_now)


class ApprovalDecision(BaseModel):
    proposal_id: str
    decision: str  # "approve" | "reject"
    approver: str
    decided_at: datetime = Field(default_factory=_now)


class Evidence(BaseModel):
    label: str
    content: str


class RunResult(BaseModel):
    playbook: str
    params: dict[str, str | bool]
    rc: int
    stdout: str = ""
    stderr: str = ""
    started_at: datetime = Field(default_factory=_now)
    finished_at: datetime | None = None

    @property
    def ok(self) -> bool:
        return self.rc == 0


class Ticket(BaseModel):
    number: str
    sys_id: str | None = None
    url: str | None = None
