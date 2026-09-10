# Individual agent identity renewal proof

`RenewalRequest` provides a bounded proof for extending an existing desktop
identity while retaining its device ID and organization/site. It supports
certificate renewal with retained keys as well as candidate certificate/broker
keys generated on the endpoint. It does not issue or activate a certificate.

## Existing identity and candidate possession

`NewRenewalRequest` receives the exact current identity, its private RSA and
broker keys, already-persisted candidate keys and a durable request UUID. The
request binds protocol/version, request/device IDs, organization/site, origin,
platform/architecture, current certificate SHA-256 and broker key, timestamp,
candidate CSR and candidate broker key.

The current RSA key signs with SHA-256/RSA-PSS and an explicit SHA-256-length salt.
The existing broker key and candidate broker key each provide an independent
NKey signature. Separate role domains prevent exchanging those broker proofs,
including when a renewal retains the same broker key. The candidate CSR must
prove its own RSA private key; only canonical base64 and SHA-256/RSA CSRs with
3072–4096-bit keys and exponent 65537 are accepted. Requested CSR subject names
must never determine the renewed certificate's identity or authority.

`ValidateRenewalProof` requires `RenewalSource` from independently loaded,
currently authorized registry state. A copied certificate supplied by the peer
is not an authoritative source. The exact existing certificate must have the
native individual-agent shape and be valid at both validation and request time.
The request has a 15-minute proof lifetime with at most one minute of future
clock skew. Scope, origin, platform, source certificate or key changes fail closed.
Both original private keys are required even when the candidate has valid proofs.

`DecodeRenewalRequest` limits JSON to 32 KiB and rejects unknown/duplicate or
case-aliased fields, nulls, malformed UTF-8 and trailing documents. The CSR and
signature fields have independent bounds. Decoding establishes wire syntax;
only proof validation against an independently authorized source authenticates it.

## Stable intent and required service lifecycle

The result includes the established semantic public-key binding and an
`IntentDigest`. The latter binds the request ID, original identity/context and
candidate public keys while excluding fresh timestamps, signature randomness and
equivalent CSR spelling. Re-signing a pending request after a transient outage
can therefore recover only the same persisted intent. A different request ID,
source or candidate key has a different intent.

Proof freshness is not replay prevention. Before this primitive is exposed as a
renewal service, the implementation must:

1. Lock current identity and organization/site membership; enforce active status,
   due-window policy, issuer lifetime, rate limits and one pending replacement.
2. Persist request ID/intent, candidate issuance, source generation and bounded
   exact retry history atomically with protected audit evidence. No request
   field may select another organization or overwrite the existing enrollment.
3. Keep the current identity usable until authenticated use of the candidate
   confirms handoff. Coordinate broker leases/disconnections, worker authority,
   inventory scope, queued commands and certificate-bound recovery tasks.
4. Persist candidate keys and activation journals in the native protected endpoint
   store before network transmission. Recover interrupted issuance/activation
   without generating a second identity or losing prior replay evidence.
5. Integrate authenticated transport, scheduling, release dependencies and the
   Windows/macOS agent runtime, then exercise actual reconnect/restart/renewal
   on physical endpoints.

These service, persistence, runtime and hardware requirements remain open. The
proof package alone is not automatic renewal or completion of ENR-01/PKI-01.

## Verification

Tests exercise fresh-key and same-key requests, semantic enrollment-key binding,
fresh-signature intent stability, both existing private keys, independent candidate
proof, cross-organization/site/device/origin rejection, exchanged proof roles,
weak keys, damaged CSRs with otherwise valid signatures, expired/future sources,
freshness boundaries, canonical encodings and wire ambiguity. The shared CI runs
these tests natively on Windows and in the Linux race suite, with bounded wire
fuzzing. No real endpoint, provider, issuer service or broker is contacted by these
proof tests.

The complete local library race suite passes, including enrollment in
**9.645 seconds** and the existing PostgreSQL registry/broker suite in
**18.581 seconds**. Wire fuzzing passes **758,034 executions** in **30.921 seconds**.
Vet and Linux/Windows builds pass. Related-library CI remains pending.
