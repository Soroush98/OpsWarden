# One image for both the agent API and the detector. Carries gcloud (Workload Identity),
# ansible-core + the OpsWarden playbooks, and the Python services.
FROM python:3.12-slim-bookworm

ENV PIP_NO_CACHE_DIR=1 PYTHONUNBUFFERED=1 DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
      curl gnupg ca-certificates apt-transport-https openssh-client \
 && echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" \
      > /etc/apt/sources.list.d/google-cloud-sdk.list \
 && curl -fsSL https://packages.cloud.google.com/apt/doc/apt-key.gpg | gpg --dearmor -o /usr/share/keyrings/cloud.google.gpg \
 && apt-get update && apt-get install -y --no-install-recommends google-cloud-cli \
 && rm -rf /var/lib/apt/lists/*

# Ansible + collections + inventory deps for gcp_compute
RUN pip install "ansible-core>=2.17" google-auth requests jmespath \
 && ansible-galaxy collection install google.cloud community.general ansible.posix

# Python services
COPY packages/ /src/packages/
COPY services/detector/ /src/services/detector/
COPY services/api/ /src/services/api/
RUN pip install /src/packages/opswarden_core /src/services/detector /src/services/api

# Playbooks
COPY ansible/ /app/ansible/
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

WORKDIR /app
ENTRYPOINT ["/entrypoint.sh"]
