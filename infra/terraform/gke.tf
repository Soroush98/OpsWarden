# Zonal GKE Standard cluster. One zone keeps the management fee at zero and the node bill small.
# Workload Identity is on from day one so pods get GCP IAM identities without JSON keys.

resource "google_service_account" "gke_nodes" {
  account_id   = "gke-nodes"
  display_name = "GKE node service account (least privilege)"
}

resource "google_project_iam_member" "gke_nodes_default" {
  project = var.project_id
  role    = "roles/container.defaultNodeServiceAccount"
  member  = "serviceAccount:${google_service_account.gke_nodes.email}"
}

resource "google_project_iam_member" "gke_nodes_registry" {
  project = var.project_id
  role    = "roles/artifactregistry.reader"
  member  = "serviceAccount:${google_service_account.gke_nodes.email}"
}

resource "google_container_cluster" "primary" {
  name     = var.cluster_name
  location = var.zone

  network    = google_compute_network.vpc.id
  subnetwork = google_compute_subnetwork.main.id

  remove_default_node_pool = true
  initial_node_count       = 1
  deletion_protection      = false

  networking_mode = "VPC_NATIVE"
  ip_allocation_policy {
    cluster_secondary_range_name  = "pods"
    services_secondary_range_name = "services"
  }

  release_channel {
    channel = "REGULAR"
  }

  workload_identity_config {
    workload_pool = "${var.project_id}.svc.id.goog"
  }

  private_cluster_config {
    enable_private_nodes    = true
    enable_private_endpoint = false
  }

  # DNS-based control plane endpoint: reachable from anywhere, authenticated by IAM,
  # so kubectl does not break every time the operator's public IP changes.
  control_plane_endpoints_config {
    dns_endpoint_config {
      allow_external_traffic = true
    }
  }

  master_authorized_networks_config {
    dynamic "cidr_blocks" {
      for_each = var.master_authorized_cidrs
      content {
        cidr_block   = cidr_blocks.value
        display_name = "authorized-${cidr_blocks.key}"
      }
    }
  }

  # Workload logs and metrics go to Elastic, not Cloud Logging. Keep only system components here.
  logging_config {
    enable_components = ["SYSTEM_COMPONENTS"]
  }

  monitoring_config {
    enable_components = ["SYSTEM_COMPONENTS"]
    managed_prometheus {
      enabled = false
    }
  }

  addons_config {
    http_load_balancing {
      disabled = false
    }
    gce_persistent_disk_csi_driver_config {
      enabled = true
    }
  }

  resource_labels = {
    project = "opswarden"
    env     = "lab"
  }

  depends_on = [
    google_project_iam_member.gke_nodes_default,
    google_compute_router_nat.nat,
  ]
}

resource "google_container_node_pool" "primary" {
  name     = "primary"
  cluster  = google_container_cluster.primary.name
  location = var.zone

  node_count = var.node_count

  management {
    auto_repair  = true
    auto_upgrade = true
  }

  node_config {
    machine_type = var.node_machine_type
    spot         = var.spot_nodes
    disk_size_gb = 50
    disk_type    = "pd-balanced"
    image_type   = "COS_CONTAINERD"

    service_account = google_service_account.gke_nodes.email
    oauth_scopes    = ["https://www.googleapis.com/auth/cloud-platform"]

    workload_metadata_config {
      mode = "GKE_METADATA"
    }

    shielded_instance_config {
      enable_secure_boot          = true
      enable_integrity_monitoring = true
    }

    metadata = {
      disable-legacy-endpoints = "true"
    }

    labels = {
      pool = "primary"
    }

    tags = ["gke-node"]
  }
}
