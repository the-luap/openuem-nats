# Bounded NetBird provider requests

`netbirdapi` sends fixed group, peer and setup-key requests to an explicitly
configured HTTPS origin with an optional path prefix. Query values are encoded;
credentials, fragments, query-bearing base URLs and path traversal are rejected.
Redirects are never followed. Requests have a five-second total limit, response
bodies are limited to one MiB and requests to 64 KiB, and provider/network errors return a neutral error.
The default transport verifies certificates and requires TLS 1.2 or newer.
A caller may supply an owned transport for tests or explicit trust configuration.

Changing requests have no automatic application retry. Setup-key POST bodies
cannot be replayed by the transport after an ambiguous reused-connection failure.
A failed request does not prove that the provider performed no action: durable
admission and recovery belong to the caller.

Peer deletion requires exactly one response with a matching IP and a valid opaque
ID. Two matches are an error. Name lookups verify the returned name. IDs cannot
inject paths. A setup-key request uses a structured JSON body with one-off use,
a one-day lifetime and usage limit one, following the official
[setup-key API](https://docs.netbird.io/api/resources/setup-keys). Both numeric and
string setup-key IDs are accepted; masked, revoked or reusable key responses are
rejected. Peer lookup filters follow the official
[peer API](https://docs.netbird.io/api/resources/peers).

Owned TLS tests cover methods/paths, encoded queries, exact identity binding,
legacy group parsing, numeric key IDs, fixed setup-key policy, neutral errors,
redirect refusal, response bounds, cancellation and unretried ambiguous creation.
Production provider or physical endpoint acceptance is separate.
