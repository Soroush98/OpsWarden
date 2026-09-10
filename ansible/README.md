# OpsWarden Ansible

Playbooks target the two Rocky 9 app servers. The VMs have no public IPs, so every connection is
tunnelled through Identity-Aware Proxy (configured in `ansible.cfg`). Inventory is discovered
dynamically from GCE labels (`role=app-server`).

## Prerequisites

- `gcloud` authenticated with access to project `opswarden-lab`.
- SSH key at `~/.ssh/google_compute_engine` (created by `gcloud compute ssh`).
- Ansible collections: `google.cloud`, `community.general`, `ansible.posix`.

## Run the SSSD join

Secrets are read from Secret Manager by the playbook itself (`lookup('pipe', 'gcloud secrets ...')`
in `inventory/group_vars/all.yml`), so nothing secret is ever passed on the command line or
written to the repo:

```bash
cd ansible
export ANSIBLE_CONFIG=$PWD/ansible.cfg
ansible-playbook playbooks/sssd.yml
```

Verify: `getent passwd soroosh`, `id soroosh`, and `sudo -l -U soroosh` on either app server.
