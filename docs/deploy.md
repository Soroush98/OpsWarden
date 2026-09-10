# Deploying OpsWarden

## Local (drives the real cluster + VMs)
```
make bootstrap            # once: project, APIs, state bucket
make apply                # VPC, GKE, VMs, registry, secrets, audit sink
make creds
make eck elastic es-templates
make kibana-import        # dashboard
kubectl apply -k deploy/openldap
kubectl apply -k deploy/agent
```
Then join the VMs and ship logs (from `ansible/`):
```
ansible-playbook playbooks/sssd.yml
ansible-playbook playbooks/elastic-agent.yml
```

## The in-cluster agent
`deploy/agent/` runs the agent (Deployment + Service) and the detector (CronJob) in namespace
`opswarden`. The pod uses Workload Identity (`opswarden-agent` GSA) to read Secret Manager, and a
dedicated SSH key (`opswarden-ssh-key`) to run Ansible against the VMs as the `opsagent` user over
the VPC. In-cluster Ansible uses the static inventory `ansible/inventory/cluster_hosts.ini`.

- Agent UI: `make agent-ui` → http://localhost:8080
- Claude-authored proposals: enable Claude in Vertex AI Model Garden, then `make vertex-on`.

## ServiceNow setup (what actually matters)

The agent talks to ServiceNow over OAuth 2.0. Three instance-side details are easy to miss and
each produces a confusing error:

1. **Attach an auth scope to the OAuth application.** In *System OAuth > Application Registry*,
   open the app and add `useraccount` under **Auth Scopes**. Without it the instance issues a
   token with an empty scope and refuses every unscoped platform API with
   `403 "Access to unscoped api is not allowed"` - including the incident table.
2. **Request that scope.** The agent sends `scope=useraccount` on the password grant
   (`OPSWARDEN_SERVICENOW_SCOPE`).
3. **Use a close code that exists in your version.** Resolving an incident without one fails with
   `Data Policy Exception: The following fields are mandatory: Resolution code`. Valid values come
   from `sys_choice` for `incident.close_code`; the default here is `Solution provided`
   (`OPSWARDEN_SERVICENOW_CLOSE_CODE`).

Basic authentication may be disabled for inbound REST on hardened instances; OAuth works either
way, so the agent prefers it whenever client credentials are configured.

## CI/CD
- `.github/workflows/ci.yml`: ruff, pytest, ansible-lint, terraform validate, kubeconform, Trivy.
- `.github/workflows/deploy.yml`: build + push + roll, via Workload Identity Federation.

### One-time WIF setup for the deploy workflow
Create a WIF pool + provider for your GitHub repo and a deploy service account with
`artifactregistry.writer` + `container.developer`, then set repo secrets `WIF_PROVIDER` and
`DEPLOY_SA`. No JSON keys are stored.
