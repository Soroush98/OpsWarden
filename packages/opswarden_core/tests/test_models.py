import pytest
from opswarden_core import Event, EventKind, ProposedAction


def test_allowlist_accepts_known_action():
    a = ProposedAction(playbook="remediate.yml",
                       params={"remediate_action": "lock_account", "remediate_username": "svc-backup"},
                       description="lock")
    a.validate_against_allowlist()  # no raise


def test_allowlist_rejects_unknown_playbook():
    with pytest.raises(ValueError):
        ProposedAction(playbook="rm-rf.yml", params={}, description="nope")


def test_allowlist_rejects_unknown_param():
    a = ProposedAction(playbook="patch.yml", params={"evil": "x"}, description="bad")
    with pytest.raises(ValueError):
        a.validate_against_allowlist()


def test_allowlist_rejects_bad_remediate_action():
    a = ProposedAction(playbook="remediate.yml",
                       params={"remediate_action": "delete_everything"}, description="bad")
    with pytest.raises(ValueError):
        a.validate_against_allowlist()


def test_event_defaults():
    e = Event(kind=EventKind.ssh_brute_force, host="app-01", source_ip="10.0.0.9", count=200)
    assert e.id.startswith("evt-")
    assert e.severity.value == "high"
