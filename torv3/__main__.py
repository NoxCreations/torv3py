"""Command-line entry point: fetch a URL through Tor."""

from __future__ import annotations

import argparse
import sys

from .client import TorClient


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="torv3",
        description="Fetch a URL through Tor without tor, SOCKS, or a proxy.",
    )
    parser.add_argument("url", help="http(s) URL, including .onion addresses")
    parser.add_argument(
        "-L",
        "--follow-redirects",
        action="store_true",
        help="follow 3xx Location headers",
    )
    parser.add_argument(
        "--allow-clearnet",
        action="store_true",
        help="allow non-.onion destinations",
    )
    parser.add_argument("--timeout", type=float, default=45.0)
    parser.add_argument("--max-bytes", type=int, default=8 * 1024 * 1024)
    parser.add_argument("--max-redirects", type=int, default=5)
    parser.add_argument("--cache", default=None, help="consensus cache path")
    parser.add_argument("--client-auth-key", default=None)
    parser.add_argument("-o", "--output", default=None, help="write the body to a file")
    parser.add_argument("-i", "--include", action="store_true", help="print response headers")
    args = parser.parse_args(argv)

    client = TorClient.create(args.cache)
    try:
        response = client.request(
            args.url,
            args.follow_redirects,
            allow_clearnet=args.allow_clearnet,
            timeout=args.timeout,
            max_bytes=args.max_bytes,
            max_redirects=args.max_redirects,
            client_auth_key=args.client_auth_key,
        )
    except KeyboardInterrupt:
        return 130
    except Exception as exc:  # noqa: BLE001 - CLI reports the concrete failure
        print(f"torv3: {exc}", file=sys.stderr)
        return 1

    body = response["body"]
    if args.output:
        with open(args.output, "wb") as handle:
            handle.write(body)
    else:
        sys.stdout.buffer.write(body)
        sys.stdout.buffer.flush()

    print(
        f"\nHTTP {response['status']} {response['url']} ({len(body)} bytes)",
        file=sys.stderr,
    )
    if args.include:
        for name, values in response["headers"].items():
            for value in values:
                print(f"{name}: {value}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
