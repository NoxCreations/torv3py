# torv3 (Python 3.14)

A native Tor v3 client: it speaks the Tor link, circuit, and hidden-service
protocols directly. There is **no `tor` process, no SOCKS proxy, and no HTTP
proxy** involved.

It fetches normal HTTP/HTTPS URLs through a three-hop exit circuit and v3
`.onion` URLs through the full descriptor → introduction → rendezvous flow.

## Requirements

- Python 3.14+
- [`cryptography`](https://pypi.org/project/cryptography/) (X25519, Ed25519
  verification, AES-CTR, RSA verification)

Install:

```bash
cd python
python3.14 -m venv .venv
. .venv/bin/activate
pip install -e .
```

Or without installing, run from this directory:

```bash
python -m torv3 --help
```

## Quick start

```python
from torv3 import fetch

response = fetch(
    "http://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion/",
    follow_redirects=True,
)
print(response["status"])
print(response["body"][:200])
```

Clearnet is blocked by default. A normal web URL needs an explicit opt-in:

```python
response = fetch("https://example.com/", follow_redirects=True, allow_clearnet=True)
```

A client can be reused, which keeps the consensus cache and entry guard warm:

```python
from torv3 import TorClient

client = TorClient.create()          # ~/.cache/torv3/consensus.json
client.request("http://example.com/", allow_clearnet=True)
client.request("http://example.com/about", allow_clearnet=True)
```

## CLI

```bash
python -m torv3 http://example.com/ --allow-clearnet -L
python -m torv3 http://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion/ -L -o page.html
```

`-L` follows up to five redirects. `-i` prints response headers to stderr.
`--cache PATH` overrides the consensus cache. `--client-auth-key` accepts a
32-byte base64 x25519 key for services that require client authorization.

## API

`TorClient.request(url, follow_redirects=False, *, allow_clearnet=False, timeout=45.0, max_bytes=8*1024*1024, max_redirects=5, client_auth_key=None)`

Returns:

```python
{
    "status": 200,                     # int, 0 if no valid HTTP response
    "headers": {"content-type": ["text/html"]},  # lower-case names, list values
    "body": b"...",                    # bytes
    "url": "http://...",               # URL that actually produced the body
}
```

- `follow_redirects=False` returns the 3xx response untouched.
- Redirect targets are re-checked against the clearnet policy. An onion page
  cannot redirect the request to the clearnet unless `allow_clearnet=True`.
- `timeout` is the per-operation budget (circuit build, descriptor fetch,
  HTTP read). A full onion request can use several of these budgets. Expect roughly 3-5 s
  for a cached clearnet request and 40-90 s for an onion request (the first one
  also builds the HSDir microdescriptor cache).
- `max_bytes` bounds the buffered response body.
- `TorError` subclasses report protocol, directory, network, onion, and stream
  failures. No internal relay address is included in the message text.

`fetch(url, ...)` is a one-shot wrapper that creates a client with the default
cache.

## What it does

1. Downloads the microdescriptor consensus from the directory authorities,
   verifies a majority of authority RSA signatures against pinned
   fingerprints, and verifies the validity window. Microdescriptors are
   fetched lazily for the few relays a circuit actually uses; the first onion
   lookup preloads the HSDir microdescriptors once and keeps them beside the
   consensus cache.
2. Builds a TLS link to an entry guard, negotiates link protocol 4, checks the
   relay's link certificate against its consensus ed25519 identity, and sends
   `NETINFO`.
3. Creates a circuit with `CREATE2`/ntor, extends it with
   `RELAY_EXTEND2`, and keeps per-hop AES-CTR and SHA-1 relay digests plus
   circuit/stream SENDME windows.
4. For clearnet, opens a stream to the destination through an `Exit` relay and
   speaks HTTP/1.0. HTTPS is negotiated end-to-end inside the circuit and the
   clearnet certificate is verified normally.
5. For onions, computes the blinded key and subcredential, fetches and
   verifies the descriptor from the responsible HSDirs, decrypts both layers,
   builds `INTRODUCE1` with hs-ntor, establishes a rendezvous point, completes
   `RENDEZVOUS2`, adds the end-to-end layer, and sends HTTP over it. Onion TLS
   certificates are accepted because the onion address authenticates the
   service.

## Security notes

- Consensus and descriptor signatures are verified; relays without an ntor
  onion key are not used.
- Entry guards are persisted in `guards.json` next to the consensus cache.
- The cache stores raw signed documents and re-verifies them on every load.
- Response bodies are buffered in memory and capped by `max_bytes`.
- HTTPS to clearnet destinations uses the system CA store. Onion HTTPS uses
  the onion address as the authentication root, matching Tor Browser.
- This is a client, not an anonymity guarantee: traffic analysis, malicious
  exits for plain HTTP, and application-level leaks are outside its scope.

## Tests

```bash
python -m unittest discover -s tests -v
python tests/live_fetch.py      # network required; onion fetch is slow
```

Verified on CPython 3.14.7 with `cryptography` 50.0.2: cold consensus
bootstrap 3.5 s, cached bootstrap 0.19 s, clearnet `example.com` HTTP 200 in
3.6 s, redirect-following to HTTPS HTTP 200, and the DuckDuckGo v3 onion
HTTP 200 (233,638 bytes) in 76.5 s.
