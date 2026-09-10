# OpsWarden services

Three Python components (uv workspace):

- **opswarden_core** (`packages/`): shared pydantic models. `ProposedAction` enforces a playbook
  allowlist so the agent can never invoke arbitrary automation.
- **detector** (`services/detector`): read-only Elasticsearch anomaly detector. Emits an `Event`
  when repeated failed logins from one source IP target a dormant account.
- **api** (`services/api`): the agent. A LangGraph flow — propose → **approve (interrupt)** →
  execute → post-check — with read-only ES tools, a deterministic remediation policy, a Claude
  narrative (via Vertex AI when configured), and a built-in approval + audit UI.

## The guardrails (interview line: "safety rails first, then the AI")

1. **Authentication and authorisation, enforced server-side.** Humans sign in against the same
   LDAP directory the agent administers; approving requires membership of the `sysadmins` group.
   The approver on an audit record is a verified directory bind, not a string the caller supplied.
   Machines (the detector) present a shared ingest token and may submit events but never approve.
2. **Read-only investigation.** The agent's Elasticsearch credential (`opswarden-reader`) has no
   write privilege, so investigation cannot mutate data.
3. **The model cannot choose actions.** Remediation comes from a deterministic policy and is
   validated against an allowlist of playbooks and typed parameters; the LLM writes only prose.
   That makes prompt injection an authorisation problem we have already solved: log lines are
   attacker-influenced, so they are framed as untrusted data, capped, and the model's output is
   schema-validated with a deterministic fallback. A successful injection can produce misleading
   text, never a privileged action.
4. **Nothing executes without a human approval** — a real LangGraph interrupt persisted in the
   checkpointer, so an approval hours later resumes the exact run.
5. **Everything is auditable** — an append-only trail plus a ServiceNow incident carrying the
   proposal, the playbook output, and the post-check.

## Known-good behaviours worth keeping

- **Repeated detections de-duplicate.** An ongoing brute force is re-reported on every scan; the
  agent suppresses repeats of an event already awaiting a decision instead of opening a ticket
  every couple of minutes.
- **Execution does not block the request.** Playbooks can run for many minutes, so approval queues
  the run and returns immediately; the proposal shows `executing` until it finishes.

## Run locally

```bash
# read-only ES reachable (port-forward for local dev)
kubectl -n observability port-forward svc/opswarden-es-internal 9200:9200 &
export OPSWARDEN_ES_PASSWORD=$(gcloud secrets versions access latest --secret=es-reader-password --project opswarden-lab)
export OPSWARDEN_ES_URL=https://localhost:9200
export OPSWARDEN_ANSIBLE_DIR=$PWD/ansible

# agent (serves the UI at http://localhost:8080)
uv run --package opswarden-api opswarden-api

# detector (single scan; add OPSWARDEN_API_URL to forward events to the agent)
uv run --package opswarden-detector opswarden-detector --once
```

## Optional integrations (activate by setting env)

- **Claude via Vertex AI**: `OPSWARDEN_VERTEX_PROJECT`, `OPSWARDEN_VERTEX_REGION` (needs Claude
  enabled in Vertex Model Garden). Without it, a deterministic narrative is used.
- **Slack approvals**: `OPSWARDEN_SLACK_WEBHOOK_URL` (+ a Slack app posting Approve/Reject to
  `/slack/interactions`). Without it, approve in the built-in UI.
- **ServiceNow PDI**: `OPSWARDEN_SERVICENOW_INSTANCE/USER/PASSWORD`. Without it, tickets are
  minted and stored locally.
