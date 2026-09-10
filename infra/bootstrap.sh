#!/usr/bin/env bash
# One-time bootstrap: creates the GCP project, links billing, enables APIs,
# and creates the GCS bucket that holds Terraform state.
# Everything after this is managed by Terraform.
set -euo pipefail

PROJECT_ID="${PROJECT_ID:-opswarden-lab}"
REGION="${REGION:-us-central1}"
BILLING_ACCOUNT="${BILLING_ACCOUNT:-}"
ORG_ID="${ORG_ID:-}"   # organization to create the project under; auto-detected if unset

if [[ -z "$ORG_ID" ]]; then
  ORG_ID="$(gcloud organizations list --format='value(ID)' 2>/dev/null | head -1)"
fi

if [[ -z "$BILLING_ACCOUNT" ]]; then
  BILLING_ACCOUNT="$(gcloud billing accounts list --filter='open=true' --format='value(name)' | head -1)"
  [[ -n "$BILLING_ACCOUNT" ]] || { echo "No open billing account found; set BILLING_ACCOUNT" >&2; exit 1; }
fi

if ! gcloud projects describe "$PROJECT_ID" >/dev/null 2>&1; then
  echo ">> creating project $PROJECT_ID${ORG_ID:+ under organization $ORG_ID}"
  gcloud projects create "$PROJECT_ID" --name="OpsWarden" ${ORG_ID:+--organization="$ORG_ID"}
elif [[ -n "$ORG_ID" ]]; then
  # Project exists: make sure it lives under the org (moves a no-org project in; no-op otherwise).
  CURRENT_PARENT="$(gcloud projects describe "$PROJECT_ID" --format='value(parent.id)' 2>/dev/null)"
  if [[ "$CURRENT_PARENT" != "$ORG_ID" ]]; then
    echo ">> moving $PROJECT_ID under organization $ORG_ID"
    gcloud beta projects move "$PROJECT_ID" --organization "$ORG_ID" --quiet ||       echo "   (move skipped; needs Project Mover/Owner on the org)"
  fi
fi

echo ">> linking billing account $BILLING_ACCOUNT"
gcloud billing projects link "$PROJECT_ID" --billing-account="$BILLING_ACCOUNT" >/dev/null

echo ">> enabling APIs (this can take a minute)"
gcloud services enable --project="$PROJECT_ID" \
  serviceusage.googleapis.com \
  cloudresourcemanager.googleapis.com \
  iam.googleapis.com \
  iamcredentials.googleapis.com \
  sts.googleapis.com \
  compute.googleapis.com \
  container.googleapis.com \
  artifactregistry.googleapis.com \
  secretmanager.googleapis.com \
  logging.googleapis.com \
  monitoring.googleapis.com \
  pubsub.googleapis.com \
  dns.googleapis.com \
  storage.googleapis.com

BUCKET="gs://${PROJECT_ID}-tfstate"
if ! gcloud storage buckets describe "$BUCKET" >/dev/null 2>&1; then
  echo ">> creating state bucket $BUCKET"
  gcloud storage buckets create "$BUCKET" --project="$PROJECT_ID" --location="$REGION" --uniform-bucket-level-access
  gcloud storage buckets update "$BUCKET" --versioning
fi

echo "Bootstrap complete."
echo "  project:      $PROJECT_ID"
echo "  state bucket: $BUCKET"
