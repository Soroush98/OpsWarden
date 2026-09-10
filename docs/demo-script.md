# Running the demo

A complete run takes about three minutes. Every command below is real: it attacks a real server,
detects it in real logs, and applies a real fix.

---

## Before you start

**1. Bring the environment up** (skip if it is already running):

```bash
make up            # start the servers and cluster nodes
make status        # wait until Elasticsearch and Kibana both report "green"
```

**2. Open the two interfaces.** Each needs its own terminal tab, because both stay running:

```bash
make agent-ui      # tab 1 - approval console at http://localhost:8080
make kibana        # tab 2 - dashboard at http://localhost:5601
```

**3. Get your logins:**

These copy each password to your clipboard rather than printing it, so nothing sensitive appears
on screen if you are sharing or capturing it. Paste into the login form; password fields are
masked.

```bash
# Kibana password (username: elastic)
make es-password | tr -d '\n' | pbcopy

# Password for the soroosh account, used to sign into the approval console
gcloud secrets versions access latest --secret=ldap-seed-user-password \
  --project opswarden-lab | tr -d '\n' | pbcopy
```

`soroosh` is a directory account and a member of the administrators group, so it can approve.
Take one at a time, since each overwrites the clipboard. On Linux, replace `pbcopy` with
`xclip -selection clipboard`. To read a password rather than copy it, drop the `| pbcopy`.

**4. In Kibana**, open **Dashboard** and choose **OpsWarden — Auth & Anomalies**. Set the time
range to **Last 1 hour** and turn on auto-refresh every 10 seconds so the chart updates live.

**5. Confirm a clean starting state.** The target account must be usable and the attacker must not
already be blocked:

```bash
cd ansible
ansible-playbook playbooks/remediate.yml -e remediate_action=unlock_account -e remediate_username=svc-backup -l app-01
ansible-playbook playbooks/remediate.yml -e remediate_action=unblock_ip -e remediate_ip=10.0.0.9
```

Both are safe to run even if nothing is locked or blocked.

---

## Step 1 — the attack

From a third terminal, launch a burst of password guesses against a dormant service account:

```bash
gcloud compute ssh attacker --tunnel-through-iap --zone us-central1-a --project opswarden-lab \
  --command 'for i in $(seq 1 40); do sshpass -p "guess$i" ssh -o StrictHostKeyChecking=no \
  -o PreferredAuthentications=password -o PubkeyAuthentication=no -o ConnectTimeout=5 \
  svc-backup@10.0.0.11 true 2>/dev/null; sleep 0.2; done; echo done'
```

**What happens:** in Kibana, within about 20 seconds the failed-login chart climbs and
`10.0.0.9` appears as the top source address.

---

## Step 2 — detection

The detector runs on its own every two minutes. To avoid waiting, trigger it:

```bash
kubectl -n opswarden create job --from=cronjob/opswarden-detector demo
kubectl -n opswarden logs -f job/demo
```

**What happens:** the log output counts the failed logins, notes the account has never logged in
successfully, and reports the event to the agent.

Now switch to the approval console and sign in as `soroosh`. A new proposal is waiting, showing a
plain-English summary, a risk assessment, the ticket number, and exactly two recommended actions.

---

## Step 3 — the human decision

This is the point the whole design exists for. The model wrote the explanation, but it did not
choose the actions and it cannot run anything outside a pre-approved list. A person decides.

Click **Approve**, then watch the agent work:

```bash
kubectl -n opswarden logs -l app=opswarden-api -f
```

**What happens:** Ansible connects to both servers and applies the change.

---

## Step 4 — proof

Confirm the world actually changed:

```bash
cd ansible
# the attacking address is now blocked on both servers
ansible role_app_server -b -m shell -a "firewall-cmd --list-rich-rules"
```

Then reload the proposal page. It now shows **executed**, a post-check confirming failed logins
have stopped, the raw playbook output as evidence, and an audit trail naming who approved it.

Finally, open the incident in ServiceNow. It carries the summary, the work notes, the command
output, and it is resolved.

---

## Two more things worth trying

**The guardrail.** In the approval console you are already signed in, so a browser session works.
From a terminal, sign in first and reuse the cookie:

```bash
PW=$(gcloud secrets versions access latest --secret=ldap-seed-user-password --project opswarden-lab)
curl -s -c /tmp/c -X POST localhost:8080/login -d "username=soroosh&password=$PW" -o /dev/null

# everything the agent is ever allowed to run
curl -s -b /tmp/c localhost:8080/allowlist

# something that is not on the list
curl -s -b /tmp/c -X POST localhost:8080/actions/validate -d 'playbook=wipe-disks.yml' -d 'params={}'

# an allowed script, but an action that is not permitted
curl -s -b /tmp/c -X POST localhost:8080/actions/validate \
  -d 'playbook=remediate.yml' -d 'params={"remediate_action":"delete_everything"}'
```

Both are refused, with the reason given.

**Approval survives a crash.** Raise a request, then destroy the agent while it is pending:

```bash
kubectl -n opswarden delete pod -l app=opswarden-api
kubectl -n opswarden rollout status deployment/opswarden-api
```

When it comes back, approve the still-pending proposal. It resumes and completes. The approval step
is durable state, not something held in memory.

---

## The other two workflows

The same approval flow handles routine service requests. On the proposals page:

- **New hire** — creates a directory account with the groups and sudo rights defined by their role,
  then proves the account can log into both servers.
- **Offboard** — disables the account, strips its group memberships, and reports any SSH keys left
  behind on the servers.
- **Patch window** — snapshots services, packages, listening ports, disk, and recent errors, runs
  the update, snapshots again, and attaches the before-and-after comparison.

Use the dry-run option when you want a quick result; a real update can take twenty minutes.

---

## Resetting to a clean state

```bash
cd ansible
ansible-playbook playbooks/remediate.yml -e remediate_action=unlock_account -e remediate_username=svc-backup -l app-01
ansible-playbook playbooks/remediate.yml -e remediate_action=unblock_ip -e remediate_ip=10.0.0.9
```

To clear the proposal list entirely:

```bash
kubectl -n opswarden exec deploy/opswarden-api -- \
  python -c "import sqlite3; d=sqlite3.connect('/data/opswarden.db'); d.execute('DELETE FROM proposals'); d.commit()"
```

---

## If something does not appear

- **No proposal after the detector runs.** The burst may have aged out of the ten-minute window, or
  fewer than ten attempts reached the server because SSH throttles rapid connections. Run the
  attack again and re-trigger the detector.
- **Nothing on the Kibana chart.** Logs take 20 to 30 seconds to arrive. Check the time range is
  "Last 1 hour" and that auto-refresh is on.
- **Cannot sign in.** The password comes from Secret Manager, printed above. Only members of the
  administrators group can approve; others can view.
- **When you are finished**, run `make down` to stop paying for idle servers.
