# Secret Manager is the source of truth for every credential. External Secrets Operator syncs
# them into the cluster through Workload Identity; Ansible reads them with gcloud. No JSON keys.

resource "random_password" "ldap_admin" {
  length  = 32
  special = false
}

resource "random_password" "ldap_sssd_bind" {
  length  = 32
  special = false
}

resource "random_password" "ldap_seed_user" {
  length  = 20
  special = false
}

resource "random_password" "ldap_svc_backup" {
  length  = 20
  special = false
}

resource "random_password" "es_agent" {
  length  = 32
  special = false
}

resource "random_password" "es_reader" {
  length  = 32
  special = false
}

# Signs the agent's login session cookies.
resource "random_password" "session_secret" {
  length  = 48
  special = false
}

# Shared secret the detector presents when posting events to the agent.
resource "random_password" "ingest_token" {
  length  = 40
  special = false
}

locals {
  secrets = {
    "ldap-admin-password"      = random_password.ldap_admin.result
    "ldap-sssd-bind-password"  = random_password.ldap_sssd_bind.result
    "ldap-seed-user-password"  = random_password.ldap_seed_user.result
    "ldap-svc-backup-password" = random_password.ldap_svc_backup.result
    "es-agent-password"        = random_password.es_agent.result
    "es-reader-password"       = random_password.es_reader.result
    "session-secret"           = random_password.session_secret.result
    "ingest-token"             = random_password.ingest_token.result
    "internal-ca-cert"         = tls_self_signed_cert.ca.cert_pem
    "ldap-server-cert"         = tls_locally_signed_cert.server["ldap"].cert_pem
    "ldap-server-key"          = tls_private_key.server["ldap"].private_key_pem
    "es-server-cert"           = tls_locally_signed_cert.server["es"].cert_pem
    "es-server-key"            = tls_private_key.server["es"].private_key_pem
  }
}

resource "google_secret_manager_secret" "this" {
  for_each = local.secrets

  secret_id = each.key

  replication {
    auto {}
  }

  labels = {
    project = "opswarden"
  }
}

resource "google_secret_manager_secret_version" "this" {
  for_each = local.secrets

  secret      = google_secret_manager_secret.this[each.key].id
  secret_data = each.value
}

# External Secrets Operator identity: one GSA, bound to the KSA external-secrets/external-secrets,
# allowed to read exactly these secrets and nothing else.
resource "google_service_account" "external_secrets" {
  account_id   = "external-secrets"
  display_name = "External Secrets Operator (reads Secret Manager via Workload Identity)"
}

resource "google_secret_manager_secret_iam_member" "external_secrets_accessor" {
  for_each = google_secret_manager_secret.this

  secret_id = each.value.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.external_secrets.email}"
}

resource "google_service_account_iam_member" "external_secrets_wi" {
  service_account_id = google_service_account.external_secrets.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "serviceAccount:${var.project_id}.svc.id.goog[external-secrets/external-secrets]"
}
