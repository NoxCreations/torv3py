"""Live smoke test: fetch one clearnet and one onion URL.

Run manually (network access is required):

    python tests/live_fetch.py

The onion fetch usually takes 20-90 seconds.
"""

from __future__ import annotations

import sys

sys.path.insert(0, ".")

from torv3 import TorClient  # noqa: E402


def main() -> int:
    client = TorClient.create()

    clearnet = client.request(
        "http://example.com/",
        follow_redirects=True,
        allow_clearnet=True,
        timeout=60,
    )
    print("clearnet:", clearnet["status"], clearnet["url"], len(clearnet["body"]))
    assert clearnet["status"] == 200
    assert b"Example Domain" in clearnet["body"]

    onion = client.request(
        "http://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion/",
        follow_redirects=True,
        timeout=60,
    )
    print("onion:", onion["status"], onion["url"], len(onion["body"]))
    assert onion["status"] == 200
    assert onion["body"]

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
