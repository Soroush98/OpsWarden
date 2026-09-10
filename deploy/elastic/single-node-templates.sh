#!/usr/bin/env bash
# Single-node lab: built-in logs/metrics templates default to 1 replica, which leaves every
# data stream yellow. Elastic's *@custom component templates are composed into the built-in
# index templates, so setting replicas there is the supported way to override it.
# Remove (or set to 1) when scaling Elasticsearch to 3 nodes.
set -euo pipefail
NS="${NS:-observability}"
ES="${ES:-opswarden}"
PW="$(kubectl -n "$NS" get secret "${ES}-es-elastic-user" -o go-template='{{.data.elastic | base64decode}}')"
for name in logs@custom metrics@custom; do
  printf "%-16s " "$name"
  kubectl -n "$NS" exec "${ES}-es-default-0" -c elasticsearch -- \
    curl -sS -k -u "elastic:${PW}" -H 'Content-Type: application/json' \
    -X PUT "https://localhost:9200/_component_template/${name}" \
    -d '{"template":{"settings":{"index.number_of_replicas":0}}}'
  echo
done
