# Identity and access for the in-cluster OpsWarden agent.
# The agent pod uses Workload Identity (no keys) to read secrets, and a dedicated SSH key to run
# Ansible directly against the app-server VMs over the VPC (pods reach VM private IPs; no IAP).

resource "google_service_account" "agent" {
  account_id   = "opswarden-agent"
  display_name = "OpsWarden agent (in-cluster): Secret Manager + Ansible"
}

# Lab-pragmatic: the agent reads existing secrets and (for JML) creates per-user password secrets.
resource "google_project_iam_member" "agent_secrets" {
  project = var.project_id
  role    = "roles/secretmanager.admin"
  member  = "serviceAccount:${google_service_account.agent.email}"
}

# Bind the Kubernetes SA opswarden/opswarden-agent to this GSA.
resource "google_service_account_iam_member" "agent_wi" {
  service_account_id = google_service_account.agent.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "serviceAccount:${var.project_id}.svc.id.goog[opswarden/opswarden-agent]"
}

# Dedicated SSH key the agent uses to reach the VMs as the local 'opsagent' user (sudo via
# google-sudoers). Public key goes into VM metadata; private key into Secret Manager.
resource "tls_private_key" "ops_agent" {
  algorithm = "ED25519"
}

resource "google_secret_manager_secret" "ops_agent_ssh" {
  secret_id = "opswarden-ssh-key"
  replication {
    auto {}
  }
  labels = { project = "opswarden" }
}

resource "google_secret_manager_secret_version" "ops_agent_ssh" {
  secret      = google_secret_manager_secret.ops_agent_ssh.id
  secret_data = tls_private_key.ops_agent.private_key_openssh
}

output "agent_gsa" {
  value = google_service_account.agent.email
}
