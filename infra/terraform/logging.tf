# GKE audit logs live in Cloud Logging. Elastic Agent cannot read Cloud Logging directly,
# so a sink copies Kubernetes API audit entries to Pub/Sub, where the GCP integration pulls them.

resource "google_pubsub_topic" "gke_audit" {
  name = "gke-audit-logs"
}

resource "google_pubsub_subscription" "gke_audit" {
  name  = "gke-audit-logs-elastic"
  topic = google_pubsub_topic.gke_audit.id

  ack_deadline_seconds       = 60
  message_retention_duration = "604800s"

  expiration_policy {
    ttl = ""
  }
}

resource "google_logging_project_sink" "gke_audit" {
  name        = "gke-audit-to-pubsub"
  destination = "pubsub.googleapis.com/${google_pubsub_topic.gke_audit.id}"

  filter = "logName:\"cloudaudit.googleapis.com\" AND protoPayload.serviceName=(\"k8s.io\" OR \"container.googleapis.com\")"

  unique_writer_identity = true
}

resource "google_pubsub_topic_iam_member" "sink_publisher" {
  topic  = google_pubsub_topic.gke_audit.id
  role   = "roles/pubsub.publisher"
  member = google_logging_project_sink.gke_audit.writer_identity
}
