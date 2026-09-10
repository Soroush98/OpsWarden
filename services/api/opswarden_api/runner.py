"""Executes allowlisted Ansible playbooks. The only component that changes infrastructure.
Params are validated against the allowlist before the process is ever spawned."""
from __future__ import annotations

import os
import subprocess
from datetime import UTC, datetime
from pathlib import Path

from opswarden_core import PLAYBOOK_ALLOWLIST, ProposedAction, RunResult

from opswarden_api.config import Settings


def run_action(action: ProposedAction, s: Settings) -> RunResult:
    action.validate_against_allowlist()  # defense in depth
    ansible_dir = Path(s.ansible_dir).resolve()
    cmd = ["ansible-playbook", f"playbooks/{action.playbook}"]
    for k, v in action.params.items():
        cmd += ["-e", f"{k}={v}"]

    env = os.environ.copy()
    env["ANSIBLE_CONFIG"] = str(ansible_dir / (s.ansible_config or "ansible.cfg"))
    env["PATH"] = f"{os.path.expanduser('~')}/.local/bin:" + env.get("PATH", "")

    started = datetime.now(UTC)
    try:
        proc = subprocess.run(cmd, cwd=ansible_dir, env=env, capture_output=True,
                              text=True, timeout=s.playbook_timeout)
        rc, out, err = proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired as exc:
        rc, out, err = 124, exc.stdout or "", f"timeout after {s.playbook_timeout}s"
    return RunResult(playbook=action.playbook, params=action.params, rc=rc,
                     stdout=out[-8000:], stderr=err[-4000:], started_at=started,
                     finished_at=datetime.now(UTC))


def known_playbooks() -> list[str]:
    return sorted(PLAYBOOK_ALLOWLIST)
