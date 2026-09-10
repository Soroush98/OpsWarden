# The "servers" that get patched and remediated. Real VMs, not pods, because patching a pod
# proves nothing. Rocky 9 (a Red Hat Enterprise Linux clone) with SSSD joined to LDAP.

resource "google_service_account" "app_server" {
  account_id   = "app-server"
  display_name = "App server VMs (LDAP-joined Ansible targets)"
}

resource "google_project_iam_member" "app_server_logging" {
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.app_server.email}"
}

resource "google_project_iam_member" "app_server_monitoring" {
  project = var.project_id
  role    = "roles/monitoring.metricWriter"
  member  = "serviceAccount:${google_service_account.app_server.email}"
}

data "google_compute_image" "rocky9" {
  family  = "rocky-linux-9"
  project = "rocky-linux-cloud"
}

data "google_compute_image" "debian12" {
  family  = "debian-12"
  project = "debian-cloud"
}

locals {
  app_servers = {
    "app-01" = "10.0.0.11"
    "app-02" = "10.0.0.12"
  }

  # opsagent = the in-cluster agent's management user (sudo via google-sudoers).
  ssh_keys_meta = join("\n", compact([
    "opsagent:${trimspace(tls_private_key.ops_agent.public_key_openssh)} opsagent",
    var.ssh_public_key != "" ? "ansible:${var.ssh_public_key}" : "",
  ]))

  app_server_metadata = {
    enable-oslogin = "FALSE" # SSSD/LDAP owns identity here; OS Login would fight it.
    ssh-keys       = local.ssh_keys_meta
  }
}

resource "google_compute_instance" "app" {
  for_each = local.app_servers

  name         = each.key
  machine_type = var.app_server_machine_type
  zone         = var.zone
  tags         = ["ssh-iap", "app-server"]

  boot_disk {
    initialize_params {
      image = data.google_compute_image.rocky9.self_link
      size  = 20
      type  = "pd-balanced"
    }
  }

  network_interface {
    subnetwork = google_compute_subnetwork.main.id
    network_ip = each.value
    # No access_config block: no public IP. SSH goes through IAP.
  }

  service_account {
    email  = google_service_account.app_server.email
    scopes = ["https://www.googleapis.com/auth/cloud-platform"]
  }

  metadata = local.app_server_metadata

  labels = {
    role = "app-server"
    env  = "lab"
  }

  allow_stopping_for_update = true
}

# Tiny box inside the VPC that runs the simulated brute force, so the alert shows a private source IP.
resource "google_compute_instance" "attacker" {
  name         = "attacker"
  machine_type = "e2-micro"
  zone         = var.zone
  tags         = ["ssh-iap", "attacker"]

  boot_disk {
    initialize_params {
      image = data.google_compute_image.debian12.self_link
      size  = 10
      type  = "pd-balanced"
    }
  }

  network_interface {
    subnetwork = google_compute_subnetwork.main.id
    network_ip = "10.0.0.9"
  }

  metadata = {
    enable-oslogin = "TRUE"
  }

  labels = {
    role = "attacker"
    env  = "lab"
  }

  allow_stopping_for_update = true
}
