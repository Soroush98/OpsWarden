SHELL      := /bin/bash
PROJECT_ID ?= opswarden-lab
REGION     ?= us-central1
ZONE       ?= us-central1-a
CLUSTER    ?= opswarden
TF_DIR     := infra/terraform
TF         := terraform -chdir=$(TF_DIR)
MY_IP      := $(shell curl -fsS https://api.ipify.org)
TF_ARGS    := -var project_id=$(PROJECT_ID) -var 'master_authorized_cidrs=["$(MY_IP)/32"]'

.PHONY: help bootstrap init plan apply destroy creds eck elastic es-templates status es-password kibana down up kibana-import vertex-on agent-ui

help: ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  %-12s %s\n", $$1, $$2}'

bootstrap: ## One-time: create the GCP project, enable APIs, create the state bucket
	PROJECT_ID=$(PROJECT_ID) REGION=$(REGION) ./infra/bootstrap.sh

init: ## terraform init
	$(TF) init -input=false

plan: ## terraform plan (authorizes your current public IP for kubectl)
	$(TF) plan -input=false $(TF_ARGS)

apply: ## terraform apply
	$(TF) apply -input=false -auto-approve $(TF_ARGS)

destroy: ## terraform destroy (keeps the project and the state bucket)
	$(TF) destroy $(TF_ARGS)

creds: ## Fetch kubeconfig for the cluster
	gcloud container clusters get-credentials $(CLUSTER) --zone $(ZONE) --project $(PROJECT_ID) --dns-endpoint

eck: ## Install or upgrade the ECK operator
	helm repo add elastic https://helm.elastic.co >/dev/null 2>&1 || true
	helm repo update elastic >/dev/null
	helm upgrade --install elastic-operator elastic/eck-operator \
	  --namespace elastic-system --create-namespace -f deploy/eck/values.yaml --wait

elastic: ## Deploy Elasticsearch and Kibana (then run deploy/elastic/single-node-templates.sh once ES is green)
	kubectl apply -k deploy/elastic

es-templates: ## Set replicas=0 for logs/metrics data streams (single-node lab)
	./deploy/elastic/single-node-templates.sh

status: ## Show Elastic resources and pods
	kubectl -n observability get elasticsearch,kibana,pods,pvc

es-password: ## Print the elastic superuser password
	@kubectl -n observability get secret opswarden-es-elastic-user -o go-template='{{.data.elastic | base64decode}}'; echo

kibana: ## Port-forward Kibana to http://localhost:5601 (user: elastic)
	kubectl -n observability port-forward svc/opswarden-kb-http 5601:5601

down: ## Stop spending: node pool to 0 and stop the VMs (disks persist)
	gcloud container clusters resize $(CLUSTER) --node-pool primary --num-nodes 0 --zone $(ZONE) --project $(PROJECT_ID) --quiet
	gcloud compute instances stop app-01 app-02 attacker --zone $(ZONE) --project $(PROJECT_ID)

up: ## Bring it back: node pool to 3 and start the VMs
	gcloud container clusters resize $(CLUSTER) --node-pool primary --num-nodes 3 --zone $(ZONE) --project $(PROJECT_ID) --quiet
	gcloud compute instances start app-01 app-02 attacker --zone $(ZONE) --project $(PROJECT_ID)

kibana-import: ## Import the OpsWarden Kibana dashboard
	@ESPW=$$(kubectl -n observability get secret opswarden-es-elastic-user -o go-template='{{.data.elastic | base64decode}}'); \
	kubectl -n observability port-forward svc/opswarden-kb-http 5601:5601 >/dev/null 2>&1 & PF=$$!; sleep 6; \
	curl -sS -u elastic:$$ESPW -H 'kbn-xsrf: true' -X POST "http://localhost:5601/api/saved_objects/_import?overwrite=true" --form file=@deploy/kibana/opswarden-dashboard.ndjson; \
	kill $$PF 2>/dev/null

vertex-on: ## Enable Claude-authored proposals (after enabling Claude in Vertex Model Garden)
	kubectl -n opswarden set env deployment/opswarden-api \
	  OPSWARDEN_VERTEX_PROJECT=$(PROJECT) OPSWARDEN_VERTEX_REGION=us-east5
	kubectl -n opswarden rollout status deployment/opswarden-api --timeout=120s

agent-ui: ## Port-forward the agent approval/audit UI to http://localhost:8080
	kubectl -n opswarden port-forward svc/opswarden-api 8080:8080
