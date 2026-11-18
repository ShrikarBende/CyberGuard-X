"""Request a held-out replay from the running backend API.

Prepare the sample once with ``python backend/ml/training/make_replay_sample.py``.
Then run this helper while the API is available; it never builds a model pipeline
or scores rows in this process.
"""
from __future__ import annotations

import argparse
import json
import time
from urllib.request import Request, urlopen


def api_json(url: str, payload: dict | None = None) -> dict:
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    request = Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST" if data else "GET")
    with urlopen(request, timeout=30) as response:
        return json.loads(response.read().decode("utf-8"))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--n", type=int, default=3000)
    parser.add_argument("--speed", type=float, default=10.0, help="rows per second; 0 is unthrottled")
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    args = parser.parse_args()
    if args.n < 1 or args.speed < 0:
        parser.error("--n must be positive and --speed nonnegative")
    base = args.base_url.rstrip("/")
    started = api_json(f"{base}/api/demo/replay", {"n": args.n, "speed": args.speed})
    print(json.dumps(started, indent=2))
    while True:
        status = api_json(f"{base}/api/demo/replay/status")
        print(json.dumps(status))
        if status.get("status") in {"completed", "stopped", "failed", "idle"}:
            break
        time.sleep(2)


if __name__ == "__main__":
    main()
