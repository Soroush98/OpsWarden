output "project_id" {
  value = var.project_id
}

output "cluster_name" {
  value = google_container_cluster.primary.name
}

output "get_credentials" {
  value = "gcloud container clusters get-credentials ${google_container_cluster.primary.name} --zone ${var.zone} --project ${var.project_id}"
}

output "app_servers" {
  value = { for k, v in google_compute_instance.app : k => v.network_interface[0].network_ip }
}

output "attacker_ip" {
  value = google_compute_instance.attacker.network_interface[0].network_ip
}

output "artifact_registry" {
  value = "${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.images.repository_id}"
}

output "gke_audit_subscription" {
  value = google_pubsub_subscription.gke_audit.id
}

output "internal_dns" {
  value = { for k, v in google_dns_record_set.ilb : k => trimsuffix(v.name, ".") }
}

output "external_secrets_gsa" {
  value = google_service_account.external_secrets.email
}
