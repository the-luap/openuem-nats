# Individual agent identity renewal

`RenewalRequest` provides a bounded proof for extending an existing desktop
identity while retaining its device ID and organization/site. It supports
certificate renewal with retained keys as well as candidate certificate/broker
keys generated on the endpoint. The proof primitive does not issue or activate a
certificate; the registry lifecycle below performs those separate transactions.

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

## Stable intent and persistent preparation

The result includes the established semantic public-key binding and an
`IntentDigest`. The latter binds the request ID, original identity/context and
candidate public keys while excluding fresh timestamps, signature randomness and
equivalent CSR spelling. Re-signing a pending request after a transient outage
can therefore recover only the same persisted intent. A different request ID,
source or candidate key has a different intent.

`registry.Store.PrepareIdentityRenewal` locks the current identity and current
organization/site/issuer membership. It verifies the existing certificate against
its stored CA, checks current metadata and both old-key proofs, and admits renewal
only within 30 days of expiry with more than five minutes remaining. Issuance must
extend the source certificate by more than 24 hours and cannot outlive the issuer.
Changing the issuer's configured origin does not silently redirect a device.

Migration 007 permanently reserves certificate public-key hashes and broker keys
for their original device, backfilling existing enrollments. An identity trigger
also protects claims by older registry clients. Pending, expired and retired keys
cannot be assigned to another device; the same device may retain its own keys.

Only one unexpired preparation for the current source is admitted. Preparation
lasts at most 168 elapsed hours, bounded by source expiry, independently of the
database session timezone. A fresh proof for the same request ID and semantic
intent returns the exact committed issuance. An expired request ID cannot be
revived; a fresh authorized request may follow it. At most 128 preparations per
device are retained; history is never automatically pruned to free retry IDs.
Capacity exhaustion fails closed and requires a separately designed lifecycle.

The original signed public request, exact source DER, issued public response and
timestamps are AES-GCM authenticated under the registry master key with distinct
device/request-bound associated data. Every read revalidates that record and its
plaintext database indexes. Issuance and key reservations commit with audit before
any public response is released. Ordinary update/delete/truncate operations cannot
rewrite these records. These guards do not defend against a database owner disabling
triggers; payload authentication still rejects changed or substituted evidence.

Preparation leaves the entire current identity unchanged. The candidate certificate
and a fresh candidate broker key are not authorized by `AccessStore` yet.

## Candidate confirmation and generation handoff

`NewRenewalConfirmation` signs the exact issued candidate certificate hash,
source hash, request/device IDs, scope, origin, target and broker key with both
candidate private keys. Its independent protocol and role domains prevent using
preparation signatures as confirmation. `DecodeRenewalConfirmation` enforces an
8 KiB strict JSON grammar; `ValidateRenewalConfirmation` requires an independently
authenticated persisted `RenewalConfirmationTarget` and the same freshness bounds
as preparation. The helper must run only after candidate keys and issuance are
durably saved: a lost reply can mean that handoff committed.

`registry.Store.ConfirmIdentityRenewal` serializes with revocation and broker
authorization under the identity lock. It authenticates pending issuance, current
scope and fresh candidate proof, then atomically replaces the certificate/key
fields, retains device ID and assignment, marks existing broker sessions for
disconnection, retires the recovery recipient epoch, and writes encrypted immutable
confirmation and audit. It does not recreate the device's command consumer or
change its stable subject names. Migration 008 retains the original confirmation.

A fresh retry after a lost acknowledgement or process restart returns the same
confirmation, even after preparation/source expiry, only while the exact candidate
generation remains current, valid and authorized. It does not repeat disconnection
side effects. Earlier confirmations cannot roll back a later generation. Revocation
and changed organization/site membership remain authoritative.

Old certificate authentication is rejected after handoff. With fresh broker keys,
new connections using the old key are denied. Existing leases are disconnected by
the existing outbox worker and expire at the bounded broker lease; this is not an
instantaneous termination guarantee. A same-key renewal intentionally continues to
authorize that same broker key, but still retires the old exact certificate.

### Recovery work and key processing

Delivered or uncertain FileVault mutations block handoff, including cancelled or
expired delivered attempts whose execution was never reconciled. A worker's
`completed` receipt also blocks until the trusted console key processor has retained
its returned key or completed verified uncertainty resolution. Migration 009 stores
that processor's immutable AES-GCM acknowledgement of the exact receipt digest.

The processor calls `AcknowledgeRotationReconciliationInTransaction` only after
its own verified result/key handling and final state/audit in the same transaction.
It must retain the native-device then agent lock order, roll back every error and
commit before reporting success. This API is not an endpoint/worker operation:
the registry can verify the signed receipt and binding, but cannot itself prove
that a caller saved the plaintext key in its own encrypted key store. Wrong hashes,
pending uncertainty, missing or corrupted acknowledgements cannot release handoff.
Older completed work requires explicit verified reconciliation before renewal;
no migration guesses that it was safely processed.

Delivered pending read-only recovery tasks must finish first. Existing certificate
epoch triggers cancel undelivered pending tasks during handoff; completed receipts
and historical ordinals remain. The endpoint must register a new server recipient
epoch before new recovery work. The original endpoint installation/replay anchor
and local recipient key must survive this certificate transition.

## Remaining application integration

This is a tested shared registry component, not automatic endpoint renewal. Before
exposing it, integrate authenticated HTTPS/gateway routing and rate limits, console
key-processing acknowledgements and recovery reconciliation, native protected
candidate storage/activation journals, lost-commit-acknowledgement recovery, broker
runtime reconnect, scheduling and pinned service/agent release dependencies.
Original enrollment anchors and immutable endpoint execution history must survive
all generations. Exercise reconnect/restart/renewal on physical Windows/macOS
endpoints separately. CA/master-key rotation and operational history-capacity
recovery are separate lifecycles. ENR-01 and PKI-01 are not complete.

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
Vet and Linux/Windows builds pass. That proof baseline's
[shared-library CI](https://github.com/the-luap/openuem-nats/actions/runs/34464554042)
passes, including native Windows and Linux/PostgreSQL/race/fuzz jobs.

Registry lifecycle tests additionally cover concurrent exact/different requests,
enrollment/reservation races, same-key and fresh-key handoff, due-window admission,
expired preparation, successive real issuance at a controlled clock, old-generation
rollback rejection, source revocation, current scope/origin changes, root-key and
payload/index tampering, audit/transaction rollback, post-audit proof expiry,
literal pre-renewal schema upgrade, elapsed-hour DST bounds, immutable evidence,
old/new broker authorization, recipient retirement and retained FileVault receipts.
They use synthetic identities and owned PostgreSQL schemas; no real endpoint,
provider or production service is contacted.

The complete lifecycle library race suite passes, including enrollment in
**10.165 seconds**, PostgreSQL registry in **27.199 seconds**, and root broker
tests in **9.658 seconds**. Confirmation wire fuzzing passes **449,004 executions**
in **30.596 seconds**. Vet and complete Linux/Windows builds pass. Published CI for
this lifecycle change must be checked independently of the earlier proof baseline.
