"""Read-only Elasticsearch tools. These are the ONLY way the agent touches Elastic — no write
privilege exists on the reader credential, so investigation can never mutate data."""
from __future__ import annotations

import httpx

from opswarden_api.config import Settings

AUTH_INDEX = "logs-system.auth-*"


class ESReader:
    def __init__(self, s: Settings):
        verify: bool | str = s.es_ca_cert if s.es_ca_cert else False
        self._c = httpx.Client(base_url=s.es_url.rstrip("/"), auth=(s.es_user, s.es_password),
                               verify=verify, timeout=20.0)

    def _search(self, body: dict) -> dict:
        r = self._c.post(f"/{AUTH_INDEX}/_search", json=body)
        r.raise_for_status()
        return r.json()

    def failed_login_context(self, source_ip: str, minutes: int = 60, n: int = 8) -> list[str]:
        body = {"size": n, "sort": [{"@timestamp": "desc"}],
                "query": {"bool": {"filter": [
                    {"term": {"source.ip": source_ip}},
                    {"term": {"event.outcome": "failure"}},
                    {"range": {"@timestamp": {"gte": f"now-{minutes}m"}}}]}},
                "_source": ["message", "@timestamp", "user.name", "host.name"]}
        return [h["_source"].get("message", "") for h in self._search(body)["hits"]["hits"]]

    def last_success(self, user: str) -> str | None:
        body = {"size": 1, "sort": [{"@timestamp": "desc"}],
                "query": {"bool": {"filter": [
                    {"term": {"event.category": "authentication"}},
                    {"term": {"event.outcome": "success"}},
                    {"term": {"user.name": user}}]}},
                "_source": ["@timestamp"]}
        hits = self._search(body)["hits"]["hits"]
        return hits[0]["_source"]["@timestamp"] if hits else None

    def failed_count(self, source_ip: str, minutes: int = 60) -> int:
        body = {"size": 0, "query": {"bool": {"filter": [
            {"term": {"source.ip": source_ip}},
            {"term": {"event.outcome": "failure"}},
            {"range": {"@timestamp": {"gte": f"now-{minutes}m"}}}]}}}
        return self._search(body)["hits"]["total"]["value"]

    def close(self) -> None:
        self._c.close()
