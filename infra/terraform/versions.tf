terraform {
  required_version = ">= 1.9"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 6.0, < 8.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
  }

  # State bucket is created by infra/bootstrap.sh (name: <project_id>-tfstate).
  backend "gcs" {
    bucket = "opswarden-lab-tfstate"
    prefix = "infra"
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
  zone    = var.zone
}
