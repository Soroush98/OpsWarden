# One VPC, one subnet. Nodes and VMs have no public IPs; egress goes through Cloud NAT.
# 10.0.0.0/24   nodes + VMs   (app-01 = .11, app-02 = .12, attacker = .9)
# 10.4.0.0/14   GKE pods (alias IPs)
# 10.8.0.0/20   GKE services

resource "google_compute_network" "vpc" {
  name                    = "opswarden-vpc"
  auto_create_subnetworks = false
  routing_mode            = "REGIONAL"
}

resource "google_compute_subnetwork" "main" {
  name                     = "opswarden-${var.region}"
  region                   = var.region
  network                  = google_compute_network.vpc.id
  ip_cidr_range            = "10.0.0.0/24"
  private_ip_google_access = true

  secondary_ip_range {
    range_name    = "pods"
    ip_cidr_range = "10.4.0.0/14"
  }

  secondary_ip_range {
    range_name    = "services"
    ip_cidr_range = "10.8.0.0/20"
  }
}

resource "google_compute_router" "router" {
  name    = "opswarden-router"
  region  = var.region
  network = google_compute_network.vpc.id
}

resource "google_compute_router_nat" "nat" {
  name                               = "opswarden-nat"
  router                             = google_compute_router.router.name
  region                             = var.region
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "ALL_SUBNETWORKS_ALL_IP_RANGES"

  log_config {
    enable = true
    filter = "ERRORS_ONLY"
  }
}

# Everything inside the VPC may talk to everything else. Deliberately permissive for a lab:
# the attacker VM must be able to reach app servers on 22, and Ansible Job pods must reach the VMs.
resource "google_compute_firewall" "allow_internal" {
  name      = "opswarden-allow-internal"
  network   = google_compute_network.vpc.name
  direction = "INGRESS"

  source_ranges = [
    google_compute_subnetwork.main.ip_cidr_range,
    google_compute_subnetwork.main.secondary_ip_range[0].ip_cidr_range,
    google_compute_subnetwork.main.secondary_ip_range[1].ip_cidr_range,
  ]

  allow {
    protocol = "tcp"
  }
  allow {
    protocol = "udp"
  }
  allow {
    protocol = "icmp"
  }
}

# SSH only via Identity-Aware Proxy TCP forwarding; no VM has a public IP.
resource "google_compute_firewall" "allow_iap_ssh" {
  name      = "opswarden-allow-iap-ssh"
  network   = google_compute_network.vpc.name
  direction = "INGRESS"

  source_ranges = ["35.235.240.0/20"]
  target_tags   = ["ssh-iap"]

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}
