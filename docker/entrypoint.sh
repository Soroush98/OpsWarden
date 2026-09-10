#!/bin/bash
# Populate secrets from Secret Manager via Workload Identity, then run the requested command.
set -e
PROJECT="${GCP_PROJECT:-opswarden-lab}"

mkdir -p /secrets
if gcloud secrets versions access latest --secret=opswarden-ssh-key --project "$PROJECT" > /secrets/opsagent_key 2>/dev/null; then
  chmod 600 /secrets/opsagent_key
fi

export OPSWARDEN_ES_PASSWORD="$(gcloud secrets versions access latest --secret=es-reader-password --project "$PROJECT" 2>/dev/null || true)"
export OPSWARDEN_SERVICENOW_PASSWORD="$(gcloud secrets versions access latest --secret=servicenow-admin-password --project "$PROJECT" 2>/dev/null || true)"
export OPSWARDEN_SERVICENOW_CLIENT_ID="$(gcloud secrets versions access latest --secret=servicenow-client-id --project "$PROJECT" 2>/dev/null || true)"
export OPSWARDEN_SERVICENOW_CLIENT_SECRET="$(gcloud secrets versions access latest --secret=servicenow-client-secret --project "$PROJECT" 2>/dev/null || true)"

# Session signing key, machine ingest token, and the CA used to StartTLS to LDAP.
export OPSWARDEN_SESSION_SECRET="$(gcloud secrets versions access latest --secret=session-secret --project "$PROJECT" 2>/dev/null || true)"
export OPSWARDEN_INGEST_TOKEN="$(gcloud secrets versions access latest --secret=ingest-token --project "$PROJECT" 2>/dev/null || true)"
export OPSWARDEN_API_TOKEN="$OPSWARDEN_INGEST_TOKEN"
if gcloud secrets versions access latest --secret=internal-ca-cert --project "$PROJECT" > /secrets/internal-ca.crt 2>/dev/null; then
  chmod 644 /secrets/internal-ca.crt
  export OPSWARDEN_LDAP_CA_CERT=/secrets/internal-ca.crt
fi

exec "$@"
