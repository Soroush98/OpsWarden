# Stable internal addresses for services that VMs must reach inside the VPC, plus a private
# DNS zone so SSSD and Elastic Agent configs use names, not IPs, and TLS certs can match them.

resource "google_compute_address" "ilb" {
  for_each = {
    ldap   = "10.0.0.20"
    es     = "10.0.0.21"
    kibana = "10.0.0.22"
  }

  name         = "${each.key}-ilb-ip"
  region       = var.region
  address_type = "INTERNAL"
  subnetwork   = google_compute_subnetwork.main.id
  address      = each.value
  purpose      = "SHARED_LOADBALANCER_VIP"
}

resource "google_dns_managed_zone" "internal" {
  name       = "opswarden-internal"
  dns_name   = "opswarden.internal."
  visibility = "private"

  private_visibility_config {
    networks {
      network_url = google_compute_network.vpc.id
    }
  }
}

resource "google_dns_record_set" "ilb" {
  for_each = google_compute_address.ilb

  name         = "${each.key}.${google_dns_managed_zone.internal.dns_name}"
  managed_zone = google_dns_managed_zone.internal.name
  type         = "A"
  ttl          = 300
  rrdatas      = [each.value.address]
}
