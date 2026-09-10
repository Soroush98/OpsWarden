# OpsWarden

**An AI teammate for IT operations that can read everything and change nothing without a human's
approval.**

OpsWarden watches the logs of a small Linux estate, notices when something is wrong, writes up
what it found in plain English, and proposes a fix. A human reads the proposal and clicks Approve
or Reject. Only then does anything change, and every step is recorded on a ticket with the raw
command output attached.

It runs on Google Kubernetes Engine against real Linux servers, real user accounts, and a real
ticketing system. Nothing here is mocked.

---

## The problem it solves

A small IT team gets an alert at 2am. Someone has to notice it, work out what happened, decide
what to do, do it, and then write down what they did so an auditor can check it later. Most of
that is slow, repetitive, and easy to get wrong when you are half asleep.

You could automate it, but handing a script the power to disable accounts and change firewalls is
how outages happen. And handing that power to a language model is worse, because a model can be
talked into things.

OpsWarden splits the job in two:

- **The machine does the tedious part**: reading thousands of log lines, correlating them, checking
  whether an account is dormant, drafting the write-up, and running the fix precisely.
- **The human keeps the decision**: nothing executes until a named, authenticated person approves
  it, and what they approved is chosen from a fixed, pre-approved list.

---

## What happens, end to end

Here is the sequence the demo shows.

1. **Something suspicious happens.** A machine starts guessing passwords for `svc-backup`, a
   service account nobody has logged into for months, on one of the app servers.
2. **The logs arrive.** Each server runs a small log shipper that forwards its authentication log
   to a central search engine, so all servers' logs are queryable in one place.
3. **A detector notices.** A small Python job runs every two minutes. It counts failed logins,
   groups them by source address, and checks whether the targeted account has *ever* logged in
   successfully. Lots of failures against a dormant account is the pattern it looks for.
4. **The agent writes it up and opens a ticket.** It creates a real incident in ServiceNow with a
   summary, a risk assessment, and the log excerpt.
5. **It proposes a fix, but cannot apply it.** The proposal is two specific actions: lock the
   account in the directory, and block the attacking address on the servers' firewalls.
6. **A human approves.** You sign in, read the proposal, and click Approve. Your identity is
   verified against the company directory, and only members of the administrators group may
   approve.
7. **The fix runs.** Automation connects to the servers over the private network and applies
   exactly the approved actions.
8. **It proves the fix worked.** It re-checks: the account can no longer authenticate, the address
   is blocked on both servers, and failed logins have stopped. All of that, plus the raw command
   output, is attached to the ticket, which is then resolved.

The same approval flow handles two other everyday jobs: **onboarding and offboarding staff**, and
**patching servers** with a before-and-after comparison so you can see exactly what changed.

---

## The safety rails

This is the part that matters, and it is why the project exists. The rails were built first and
the AI was added last.

**1. The AI cannot choose what to do.**
When an event arrives, a plain, deterministic policy decides which actions are appropriate. The
language model only writes the human-readable explanation. Even a perfectly manipulated model
cannot invent an action, because it is never asked to.

**2. There is a fixed list of things that can ever run.**
Every action names one of a handful of pre-written automation scripts, with a fixed set of allowed
parameters. Anything else is rejected before a human ever sees it. You can ask the running system
to prove this:

```bash
curl -X POST localhost:8080/actions/validate -d 'playbook=wipe-disks.yml' -d 'params={}'
# {"allowed": false, "reason": "playbook 'wipe-disks.yml' is not in the allowlist"}
```

**3. The AI can look, but not touch.**
Its database credential is read-only. Investigation physically cannot modify data.

**4. Approval is a real, verified human decision.**
People sign in against the same directory the system administers. Approving requires membership of
the administrators group. The name on the audit record is a verified login, not text someone typed
into a form. The detector has its own credential that lets it report events but never approve one.

**5. Untrusted text is treated as untrusted.**
Log lines contain attacker-supplied content, so they are clearly labelled as data rather than
instructions, capped in size, and the model's reply is checked against a strict schema. If the
model fails, refuses, or returns nonsense, the system falls back to a plain generated summary and
carries on.

**6. Everything is recorded.**
Every proposal, decision, command, and result lands in an append-only trail and on the ticket.

---

## What it is built from, in plain terms

| Piece | What it actually is | Why it is here |
|---|---|---|
| **Terraform** | Infrastructure defined as text files | The whole environment can be destroyed and rebuilt from scratch |
| **Kubernetes (GKE)** | Google's managed platform for running containers | Runs the agent, the detector, and the log search cluster |
| **Compute Engine VMs** | Two ordinary Linux servers (Rocky 9) | The things being managed. Patching a real server proves more than patching a container |
| **OpenLDAP** | A central directory of user accounts and groups | One place that defines who exists and what they may do |
| **SSSD** | The Linux client that talks to that directory | Lets people log into the servers with their directory account |
| **Elasticsearch & Kibana** | A search engine for logs, and its dashboard | Where logs are stored, searched, and charted |
| **Elastic Agent** | A small log shipper on each server | Sends authentication logs to Elasticsearch |
| **Ansible** | A tool that runs defined tasks on servers over SSH | The only thing that ever changes a server |
| **FastAPI + LangGraph** | A Python web service, and a library for multi-step workflows | The agent: it holds the approval step as a durable pause |
| **Claude (via Vertex AI)** | A large language model | Writes the human-readable summary and risk assessment |
| **ServiceNow** | An IT service management system | The official record: tickets, notes, and evidence |
| **Secret Manager** | Google's encrypted secret store | Holds every password and key. None are in this repository |

---

## Try it yourself

**You will need:** a Google Cloud account with billing enabled, and `gcloud`, `terraform`,
`kubectl`, `helm`, and `ansible` installed locally.

```bash
make bootstrap      # create the cloud project, enable APIs, create state storage
make apply          # build the network, cluster, servers, and secrets (~12 minutes)
make creds          # point kubectl at the new cluster
make eck elastic    # install the log search cluster
make es-templates   # single-node tuning
make kibana-import  # load the dashboard

kubectl apply -k deploy/openldap   # the directory
kubectl apply -k deploy/agent      # the agent and detector
```

Then join the servers to the directory and start shipping their logs:

```bash
cd ansible
ansible-playbook playbooks/sssd.yml
ansible-playbook playbooks/elastic-agent.yml
```

**Stop paying while you sleep.** `make down` shuts off the servers and cluster nodes but keeps all
data; `make up` brings it back in about three minutes.

Full detail, including the ServiceNow setup, is in [docs/deploy.md](docs/deploy.md).

---

## Running the demo

Step-by-step, with the exact commands and what you should see:
**[docs/demo-script.md](docs/demo-script.md)**.

The short version:

```bash
make agent-ui      # the approval console at http://localhost:8080
make kibana        # the log dashboard at http://localhost:5601
```

Then start a simulated password-guessing attack, watch it appear on the dashboard, watch a proposal
show up in the console, click Approve, and watch the account get locked and the address blocked.

---

## How the repository is organised

```
infra/terraform/   the cloud environment: network, cluster, servers, secrets, certificates
deploy/            what runs on Kubernetes: log search, directory, the agent, the dashboard
services/          the Python: shared models, the detector, and the agent itself
ansible/           the automation that is allowed to change servers
docker/            the container image shared by the agent and detector
docs/              architecture, deployment, and the demo script
.github/workflows/ automated checks on every change
```

---

## Cost

Roughly **USD 185 per month** if left running continuously: three small Kubernetes nodes, two small
servers, one tiny attacker machine, and about 100 GB of disk. Using `make down` overnight cuts that
to a fraction. Setting `spot_nodes = true` reduces node cost by about two thirds during development.

---

## Honest limitations

- The approval console is reached through a local tunnel rather than published on the internet,
  which is deliberate for a system that can disable accounts. Putting it online would need a
  proper identity proxy in front.
- It manages two servers. The design would scale, but it has not been tested at scale.
- The language model writes the explanation only. If it is unavailable, the system keeps working
  with a generated summary.
- Automated tests cover the security rules, the allowlist, and the parsing. They do not cover the
  infrastructure code.
