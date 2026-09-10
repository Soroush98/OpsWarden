from __future__ import annotations

import argparse
import sys
import time

import httpx

from detector.config import Settings
from detector.es import ES
from detector.rules import ALL_RULES


def scan_once(es: ES, s: Settings) -> int:
    found = 0
    for rule in ALL_RULES:
        for event in rule(es, s):
            found += 1
            line = (f"[{event.severity.value.upper()}] {event.kind.value}: "
                    f"{event.count} failed logins from {event.source_ip} against "
                    f"{event.target_user}@{event.host} "
                    f"(dormant: {event.dormant_days} days)")
            print(line, flush=True)
            if s.api_url:
                try:
                    httpx.post(f"{s.api_url.rstrip('/')}/events",
                               json=event.model_dump(mode="json"),
                               headers={"X-OpsWarden-Token": s.api_token},
                               timeout=15).raise_for_status()
                    print(f"  -> posted {event.id} to agent", flush=True)
                except Exception as exc:  # noqa: BLE001
                    print(f"  -> FAILED to post {event.id}: {exc}", file=sys.stderr, flush=True)
    return found


def main() -> None:
    ap = argparse.ArgumentParser(description="OpsWarden Elasticsearch anomaly detector")
    ap.add_argument("--once", action="store_true", help="scan a single time and exit")
    args = ap.parse_args()

    s = Settings()
    es = ES(s)
    try:
        if args.once:
            n = scan_once(es, s)
            print(f"scan complete: {n} event(s)")
            return
        print(f"detector polling every {s.poll_seconds}s "
              f"(threshold={s.brute_force_threshold}/{s.window_minutes}m)", flush=True)
        while True:
            scan_once(es, s)
            time.sleep(s.poll_seconds)
    finally:
        es.close()


if __name__ == "__main__":
    main()
