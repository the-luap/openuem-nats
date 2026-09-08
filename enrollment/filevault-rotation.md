# FileVault rotation transport and registry

This package implements an encrypted rotation protocol and its PostgreSQL
registry. It does not execute a FileVault command, enable a console action, or
advertise endpoint rotation support. The protected endpoint journal, OS driver,
worker subscriber and console escrow workflow must be integrated separately
before enabling rotation. Existing FileVault validation uses its unchanged v1
protocol and remains a read-only operation.

## Protocol boundaries

Rotation uses the individual agent's `rotation` request subject. Every request and
reply includes `version: 1` and `protocol: "filevault-rotation"`. Receivers reject
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
recoverable outcome must produce uncertainty and invoke the independent native
escrow recovery workflow. The attempt bound allows a fixed-size protected journal
without deleting replay-prevention evidence.

The console must preserve all previously escrowed keys, reconcile a returned key
with any newer native escrow response, and avoid overwriting a newer unrelated
key. An uncertain attempt requires independent proof of the current key before
being resolved; this registry exposes no automatic uncertainty-resolution API.
Native escrow must already be active because a process can fail after the OS
changes a key but before its encrypted receipt is persisted. Endpoint execution,
uncertainty resolution and physical-device acceptance remain separate work.

## Validation

Protocol tests cover both encrypted directions, signature/context/nonce tampering,
purpose separation, expired tasks versus late receipts, secret-buffer clearing,
strict wire decoding and fuzz seeds. PostgreSQL race tests cover concurrent polls,
atomic audit rollback, immutable receipts, ordinal limits, conflicting validation,
recipient replacement, revocation, lock-wait certificate expiry, late returned
keys, and a 514-device bounded maintenance test with locked and uncertain rows.
These tests use synthetic keys and disposable schemas; they execute no device
commands.
