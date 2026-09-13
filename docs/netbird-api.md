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

## Managed registration keys

`ManagedKeyRequest` binds a canonical registration UUID, up to 100 unique group
IDs and the extra-DNS choice to a deterministic creation body. It uses one-off
type, usage limit one, a 24-hour requested lifetime and non-ephemeral peers.
`Digest` returns that exact body's SHA-256 so the caller can commit admission
before the provider request. Group ordering is canonical without changing the
caller's slice.

`CreateManagedKey` checks the returned name, ID, complete policy, group set,
unused/unrevoked state and expiry before returning the full secret. Duplicate or
aliased fields, missing/null policy fields, unsafe keys and oversized responses
fail. Expiry must permit the bounded device command and cannot exceed the
requested day plus five minutes of provider clock allowance. A failed response
may follow successful remote creation and never triggers another POST.

The [provider API](https://docs.netbird.io/api/resources/setup-keys) returns a full
key when created and a masked value on later reads. The caller must encrypt and
durably retain the original result before delivery. It must not attempt to
recover a missing secret by creating another key.

`ObserveManagedKey` queries only the ID retained from that creation. It returns
metadata without the key/masked-key field. A bounded 404 response distinguishes
absence; authorization failures, redirects, malformed responses and transport
errors remain unknown. `SameOwnership` compares retained ID, name, expiry and
creation policy while allowing usage/revocation state to change. A name or an
agent-reported address alone is never a cleanup ownership proof. Callers retain
the original provider authority and commit deletion intent before `DeleteKey`.

Owned TLS tests cover deterministic creation, exact returned policy, masked
observations, cleanup ID correlation, read-only absence, cancellation and no
retry after response loss. These helpers are provider boundaries; complete
registration admission, encrypted persistence and UI integration remain in the
console/agent workflow.

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
