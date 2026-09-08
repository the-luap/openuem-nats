# Private FileVault validation transport

Recovery protocol version 1 adds the individual agent `recovery` request subject.
It does not change the durable command stream. Update generated broker permissions
when upgrading the service. A worker advertises `recovery_task_version: 1` only
after its handlers and registry migration 004 are available; older workers and
agents leave the capability absent.

The Mac generates a separate X25519 recipient key in its protected local store.
Registration uses a five-minute server challenge signed by the current individual
agent RSA certificate. That certificate remains signature-only. Recipient changes
create a new epoch, cancel pending tasks and cannot be rolled back by replaying a
previous signed challenge. All requests also require broker subject authorization.

The console encrypts a recovery key and random 32-byte nonce with RFC 9180 HPKE
(X25519, HKDF-SHA256, AES-256-GCM). The authenticated context binds the agent,
tenant, site, current signing certificate, native Mac, recovery-key version,
recipient epoch, task UUID and expiry. Routing workers receive only ciphertext.
Only one pending task per agent is allowed. Tasks expire within 24 hours, or
earlier when the certificate expires.

The endpoint returns a signature over the exact context, nonce and outcome:
`valid`, `invalid`, `unavailable` or `unsupported`. A nonce alone would not protect
the outcome from modification by a routing service. Registration and result writes
commit their audit records in the same transaction. Exact duplicate acknowledgments
are idempotent while the task remains unexpired and its identity remains current.
Terminal tasks retain the signed result and erase their encrypted envelope.
Maintenance erases up to 256 stale envelopes per pass, including offline agents.

This protocol does not itself authorize a console operation or prove the physical
Mac association. The console must lock and recheck its permission, native device,
canonical association, current recovery key and current agent identity before
queueing or accepting verification. It must verify the signed result again before
marking a key verified. A compromised endpoint can misreport an OS check; this is
not hardware attestation. Physical Mac acceptance remains a separate requirement.

Tests use generated fixture keys, isolated PostgreSQL schemas and test processes;
they do not unlock a disk or invoke FileVault on a real device. Private byte buffers
are cleared at ownership boundaries. Go cryptographic implementations may retain
internal copies, so complete process-memory zeroization is not claimed.
