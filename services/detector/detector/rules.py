"""Detection rules. Each returns Events; the agent decides what to propose."""
from __future__ import annotations

from datetime import UTC, datetime

from opswarden_core import Event, EventKind, Severity

from detector.config import Settings
from detector.es import ES

AUTH_INDEX = "logs-system.auth-*"


def _last_success_age_days(es: ES, user: str) -> int | None:
    """Days since the user's last successful login, or None if never seen."""
    body = {
        "size": 1,
        "sort": [{"@timestamp": "desc"}],
        "query": {"bool": {"filter": [
            {"term": {"event.category": "authentication"}},
            {"term": {"event.outcome": "success"}},
            {"term": {"user.name": user}},
        ]}},
        "_source": ["@timestamp"],
    }
    hits = es.search(AUTH_INDEX, body).get("hits", {}).get("hits", [])
    if not hits:
        return None
    ts = datetime.fromisoformat(hits[0]["_source"]["@timestamp"].replace("Z", "+00:00"))
    return (datetime.now(UTC) - ts).days


def _sample_messages(es: ES, source_ip: str, minutes: int, n: int = 5) -> list[str]:
    body = {
        "size": n,
        "sort": [{"@timestamp": "desc"}],
        "query": {"bool": {"filter": [
            {"term": {"source.ip": source_ip}},
            {"term": {"event.outcome": "failure"}},
            {"range": {"@timestamp": {"gte": f"now-{minutes}m"}}},
        ]}},
        "_source": ["message"],
    }
    hits = es.search(AUTH_INDEX, body).get("hits", {}).get("hits", [])
    return [h["_source"].get("message", "") for h in hits]


def detect_ssh_brute_force(es: ES, s: Settings) -> list[Event]:
    """Failed SSH logins from one source IP over threshold in the window,
    where the targeted account is dormant."""
    body = {
        "size": 0,
        "query": {"bool": {"filter": [
            {"term": {"event.category": "authentication"}},
            {"term": {"event.outcome": "failure"}},
            {"range": {"@timestamp": {"gte": f"now-{s.window_minutes}m"}}},
        ]}},
        "aggs": {"by_ip": {"terms": {"field": "source.ip", "size": 20},
                           "aggs": {
                               "by_user": {"terms": {"field": "user.name", "size": 3}},
                               "by_host": {"terms": {"field": "host.name", "size": 3}},
                               "first": {"min": {"field": "@timestamp"}},
                               "last": {"max": {"field": "@timestamp"}},
                           }}},
    }
    resp = es.search(AUTH_INDEX, body)
    events: list[Event] = []
    for ip_bucket in resp.get("aggregations", {}).get("by_ip", {}).get("buckets", []):
        if ip_bucket["doc_count"] < s.brute_force_threshold:
            continue
        source_ip = ip_bucket["key"]
        users = ip_bucket["by_user"]["buckets"]
        hosts = ip_bucket["by_host"]["buckets"]
        top_user = users[0]["key"] if users else None
        top_host = hosts[0]["key"] if hosts else "unknown"
        if not top_user:
            continue
        age = _last_success_age_days(es, top_user)
        dormant = age is None or age >= s.dormant_days
        if not dormant:
            continue
        events.append(Event(
            kind=EventKind.ssh_brute_force,
            severity=Severity.high,
            host=top_host,
            target_user=top_user,
            source_ip=source_ip,
            count=ip_bucket["doc_count"],
            window_minutes=s.window_minutes,
            dormant_days=age,
            first_seen=_parse(ip_bucket["first"].get("value_as_string")),
            last_seen=_parse(ip_bucket["last"].get("value_as_string")),
            raw_context=_sample_messages(es, source_ip, s.window_minutes),
        ))
    return events


def _parse(v: str | None):
    if not v:
        return None
    return datetime.fromisoformat(v.replace("Z", "+00:00"))


ALL_RULES = [detect_ssh_brute_force]
