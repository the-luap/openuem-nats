# FileVault rotation transport and registry

This package implements an encrypted rotation protocol and its PostgreSQL
registry. It does not execute a FileVault command, enable a console action, or
advertise endpoint rotation support. The protected endpoint journal, OS driver,
worker subscriber and console escrow workflow must be integrated separately
before enabling rotation. Existing FileVault validation uses its unchanged v1
protocol and remains a read-only operation.

The optional agent configuration field `rotation_task_version: 2` negotiates this
separate capability. Absence or an unsupported version cannot enable execution.

## Protocol boundaries

Rotation uses the individual agent's `rotation` request subject. Every request and
reply includes `version: 2` and `protocol: "filevault-rotation"`. Receivers reject
unknown fields, duplicate fields, noncanonical JSON, oversized messages and other
protocols' acknowledgements. The worker must authenticate the subject, active
identity, organization/site, body agent ID and private reply prefix before calling
`AccessStore.HandleRotation`.

The comparable `RotationContext` binds all of the following:

- Active agent ID, organization, site and signing-certificate digest.
- Task ID, canonical native Mac ID, source recovery-key version and recipient epoch.
- Mutation deadline, no more than 15 minutes from admission.
- Confirmed native escrow configuration ID.
- Permanent per-identity attempt ordinal, from 1 through 128.
- A separate per-attempt console X25519 return public key.

`EncryptRotationTask` encrypts the old 29-byte personal recovery key and a random
32-byte nonce to the registered endpoint recipient. `NewRotationResult` encrypts
any returned key and the same nonce to the console return recipient, then signs
the complete context, outcome, nonce and encrypted return envelope with the
current enrollment certificate's RSA signing key. The request and return public
keys must differ. Both envelopes use RFC 9180 HPKE with X25519, HKDF-SHA256 and
AES-256-GCM; separate domains distinguish validation, rotation requests, rotation
returns and result signatures. Full context is bound into HPKE info and AAD.

The routing worker needs neither a PRK nor the console master key. The console
must retain its private return key encrypted under its own master key and store
the expected context and nonce digest independently of the routing result. It
must verify current authority and that independent expectation before invoking
`OpenRotationResult`. The decryption method checks context, nonce digest, signing
certificate, signature, return recipient and the decrypted nonce.

`HandleRotationInTransaction` lets a worker retain its inventory-scope locks in
the same transaction as registry delivery, receipt storage and audit. That caller
must use the same database, roll back any error and commit before replying.
The ordinary `HandleRotation` wrapper owns and commits its own transaction.

`RotationSecret` exposes borrowed byte slices and has no JSON representation.
Call `Close` promptly to clear them. Do not log PRKs, place them in command
arguments or environment variables, or retain them in a journal. A journal may
retain the nonce and encrypted receipt. As with other Go cryptographic code,
clearing owned buffers does not guarantee erasure of all runtime/internal copies.

## Attempt lifecycle

Migration `005_rotation_tasks.sql` stores permanent context/ordinal records,
encrypted requests, nonce digests and encrypted signed receipts. The console
calls `NextRotationOrdinal` and `QueueRotationTask` in the same authorized
transaction, retaining the identity lock between allocation and insertion.
Cancelled, expired and unsuccessful attempts still consume their ordinal. No
ordinal is reused; after 128 attempts this identity cannot queue another rotation.

Queueing a rotation cancels pending read-only validation and erases its request
ciphertext. Pending or uncertain rotation blocks another rotation and ordinary
validation. The console must separately enforce device-security permission,
canonical Mac association, current validated source PRK, a confirmed active
native escrow profile, recent native evidence and its audit transaction.

The queued mutation deadline must leave at least `RotationReceiptGrace` (two
minutes) before both the parsed certificate and registry certificate lifetime
expire. The endpoint must independently reserve the same grace. Signing and
durable publication happen while the certificate is still valid, even when an
OS operation consumes its entire execution deadline. This reserve does not make
OS mutation and native keychain writes atomic or remove the native escrow fallback.

| Event | Stored status | Delivery behavior |
| --- | --- | --- |
| Queued and live | `pending` | Deliver the same encrypted task. |
| Undelivered task expires | `expired` | Erase the encrypted request; reject results. |
| Delivered task expires | `uncertain` | Erase the request; ask only for its cached receipt. |
| Signed `uncertain` result | `uncertain` | Retain the immutable receipt and block further mutation. |
| Signed `rotated`, `unverified`, `invalid`, `unavailable` or `unsupported` result | `completed` | Retain the immutable encrypted receipt; erase the request. |
| Identity or recipient loses authority | `cancelled` | Stop delivery and erase unresolved request ciphertext. |

`rotated` means the endpoint also validated the returned key against the volume.
`unverified` retains a returned candidate whose validation could not complete.
`invalid` means the old key failed validation before any mutation. `unavailable`
and `unsupported` also indicate no admitted mutation. `uncertain` means an
admitted mutation has no recoverable output and must never trigger an automatic
retry. A registry `completed` status records receipt delivery, not console escrow
acceptance or successful device rotation.

The mutation deadline prevents new execution, but does not discard a key already
changed on a device. A late result is accepted only if the registry proves that
this exact task was delivered before expiry, and its current certificate, scope,
recipient epoch, context and nonce still match. First delivery time is preserved
across polls. A byte-identical receipt retry is idempotent; a conflicting receipt
is rejected. Result storage, request erasure and audit insertion commit together.

Identity and recipient triggers cancel unresolved tasks even when an older
component updates those rows. Maintenance processes at most 256 stale records,
skips locked rows, excludes still-authorized uncertainty from its candidate batch
and preserves completed encrypted receipts. Site ownership and naturally elapsed
certificate expiry are checked as well as explicit revocation.

## Required endpoint and console integration

Before invoking an OS mutation, an endpoint must durably create an immutable
intent under the exact identity, ordinal, context and nonce. Once that intent
exists, a task retry or process restart must never execute the mutation again.
Persist the signed encrypted outcome before transmitting it. An intent without a
recoverable outcome must never be replayed. During the same kernel boot, a freed
parent lease does not exclude a surviving command. Wait for recorded process
termination or a different boot session before signing stopping evidence; keep
the independent native escrow recovery workflow available. The attempt bound allows a fixed-size protected journal
without deleting replay-prevention evidence.

The console must preserve all previously escrowed keys, reconcile a returned key
with any newer native escrow response, and avoid overwriting a newer unrelated
key. An uncertain attempt requires independent proof of the current key before
being resolved. Migration 006 adds explicit, caller-authorized recovery APIs:
`QueueRotationValidation` requires the exact signed uncertainty receipt with
`execution_stopped: true` before admitting a read-only validation task. Deadline
expiry or uncertainty without stopping evidence remains blocked. The selected proof is bound to this rotation, identity, recipient and
native Mac; replacing the proof cancels its pending predecessor. Ordinary validation
and another mutation remain blocked while this recovery runs.

`ResolveRotation` requires the selected subsequent proof's signed `valid` result,
current authority, exact context and nonce, and a pre-expiry delivery/completion.
The console must independently check its own expectation, current key and native
association in the same transaction. Resolution commits its audit atomically and
retains the original uncertainty receipt, ordinal and proof. It does not retry
the mutation or turn an invalid/unavailable proof into success.
Native escrow must already be active because a process can fail after the OS
changes a key but before its encrypted receipt is persisted. Endpoint execution,
console integration and physical-device acceptance remain separate work.

## Validation

Protocol tests cover both encrypted directions, signature/context/nonce tampering,
purpose separation, expired tasks versus late receipts, secret-buffer clearing,
strict wire decoding and fuzz seeds. PostgreSQL race tests cover concurrent polls,
atomic audit rollback, immutable receipts, ordinal limits, conflicting validation,
recipient replacement, revocation, lock-wait certificate expiry, late returned
keys, and a 514-device bounded maintenance test with locked and uncertain rows.
Resolution tests reject live execution, receipt-free uncertainty, altered stop
evidence, unfinished/invalid/superseded proofs and changed proof context. They also
cover caller rollback, audit rollback, retained evidence and subsequent ordinals.
These tests use synthetic keys and disposable schemas; they execute no device
commands.

## Version 2 stopping evidence

Version 2 is required for rotation capability negotiation and request/reply
messages. The encrypted task context and domain bindings remain compatible with
stored records. This permits receipt recovery without upgrading a version 1
uncertainty claim into proof that execution stopped. The optional signed
`execution_stopped` field is valid only on an `uncertain` result; it must be true
before `QueueRotationValidation` or `ResolveRotation` can admit an old-key check
as a resolution. Removing or adding this field invalidates the signature.

An agent process lease alone does not prove that a previously launched command
stopped: the command can outlive the parent and its descriptor. The updated agent
records the kernel boot-session UUID in its immutable admission record. It signs
stopping evidence only after reaping its exact mutation process or after observing
a different boot session from that record. After a crash during the same boot,
intent-only recovery waits and never reruns the mutation. New agents and workers
must both negotiate version 2. Legacy uncertainty receipts remain readable and
immutable but do not authorize automatic resolution.
