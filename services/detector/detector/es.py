from __future__ import annotations

import httpx

from detector.config import Settings


class ES:
    """Minimal read-only Elasticsearch client (httpx)."""

    def __init__(self, s: Settings):
        verify: bool | str = s.es_ca_cert if s.es_ca_cert else False
        self._client = httpx.Client(
            base_url=s.es_url.rstrip("/"),
            auth=(s.es_user, s.es_password),
            verify=verify,
            timeout=20.0,
        )

    def search(self, index: str, body: dict) -> dict:
        r = self._client.post(f"/{index}/_search", json=body)
        r.raise_for_status()
        return r.json()

    def close(self) -> None:
        self._client.close()
