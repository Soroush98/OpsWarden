resource "google_artifact_registry_repository" "images" {
  location      = var.region
  repository_id = "opswarden"
  format        = "DOCKER"
  description   = "OpsWarden service images (api, detector, ansible runner)"

  labels = {
    project = "opswarden"
  }
}
