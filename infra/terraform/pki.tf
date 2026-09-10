# A small internal CA. VMs trust one CA for both LDAPS and Elasticsearch.
# Keys live in Terraform state (private, versioned GCS bucket) and in Secret Manager.

resource "tls_private_key" "ca" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P256"
}

resource "tls_self_signed_cert" "ca" {
  private_key_pem = tls_private_key.ca.private_key_pem

  subject {
    common_name  = "OpsWarden Lab Internal CA"
    organization = "OpsWarden Lab"
  }

  is_ca_certificate     = true
  validity_period_hours = 87600
  allowed_uses          = ["cert_signing", "crl_signing", "digital_signature"]
}

locals {
  server_certs = {
    ldap = {
      dns_names = [
        "ldap.opswarden.internal",
        "openldap",
        "openldap.identity",
        "openldap.identity.svc",
        "openldap.identity.svc.cluster.local",
        "localhost",
      ]
      ip_addresses = ["10.0.0.20", "127.0.0.1"]
    }
    es = {
      dns_names = [
        "es.opswarden.internal",
        "opswarden-es-http",
        "opswarden-es-http.observability",
        "opswarden-es-http.observability.svc",
        "opswarden-es-http.observability.svc.cluster.local",
        "opswarden-es-internal-http",
        "opswarden-es-internal-http.observability",
        "opswarden-es-internal-http.observability.svc",
        "opswarden-es-internal-http.observability.svc.cluster.local",
        "*.observability.svc",
        "*.observability.svc.cluster.local",
        "localhost",
      ]
      ip_addresses = ["10.0.0.21", "127.0.0.1"]
    }
  }
}

resource "tls_private_key" "server" {
  for_each = local.server_certs

  algorithm   = "ECDSA"
  ecdsa_curve = "P256"
}

resource "tls_cert_request" "server" {
  for_each = local.server_certs

  private_key_pem = tls_private_key.server[each.key].private_key_pem
  dns_names       = each.value.dns_names
  ip_addresses    = each.value.ip_addresses

  subject {
    common_name  = each.value.dns_names[0]
    organization = "OpsWarden Lab"
  }
}

resource "tls_locally_signed_cert" "server" {
  for_each = local.server_certs

  cert_request_pem   = tls_cert_request.server[each.key].cert_request_pem
  ca_private_key_pem = tls_private_key.ca.private_key_pem
  ca_cert_pem        = tls_self_signed_cert.ca.cert_pem

  validity_period_hours = 17520
  early_renewal_hours   = 720
  allowed_uses          = ["key_encipherment", "digital_signature", "server_auth"]
}
