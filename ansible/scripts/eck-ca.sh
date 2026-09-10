#!/usr/bin/env bash
# Prints the Elasticsearch HTTP CA that ECK generated, for the VMs' Elastic Agent to trust.
set -euo pipefail
kubectl -n observability get secret opswarden-es-http-certs-public \
  -o go-template='{{ index .data "ca.crt" | base64decode }}'
