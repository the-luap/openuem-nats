# Authenticated Windows software tasks

This package defines the private `software` RPC and the registry transaction
boundary for individually enrolled Windows agents. It does not run an installer.
Console preparation is separate from explicit dispatch authorization. A prepared
catalog request must not be automatically promoted into an executable task.

The executable plan accepts immutable MSI/EXE install or remove instructions,
architecture, minimum OS, exact machine detection and approved exit/restart codes.
An artifact has a canonical HTTPS URL and SHA-256 digest. Private URLs, arguments
and MSI property values are available only through the explicit plan codec or
decryption; ordinary formatting is redacted and ordinary JSON encoding fails.
WinGet coordinates and x86 packages are not executable plans in this protocol.
Resolving and approving immutable WinGet artifacts remains separate work.

## Sender and recipient authentication

HPKE protects confidentiality but does not authenticate the sender. A trusted
console seals each plan to a dedicated X25519 software recipient, then signs the
whole envelope with an ephemeral Ed25519 command key. The command certificate is
issued by the exact enrollment CA, has only digital-signature and code-signing
usage, identifies the tenant/task in its URI, and expires with the task. The
endpoint uses the CA from its already validated local enrollment, never a root
supplied by the incoming task. The private command key is discarded after use.

The authenticated context binds permanent organization/site/device ownership,
certificate generation, task/preparation/revision/recipient IDs, exact plan hash,
safe detection/exit expectations and lifetime. The endpoint checks all of these
at the current time before starting new work. Each certificate generation needs
a new protected software encryption key; FileVault, broker and signing keys are
separate. Recipient registration requires a nonce challenge signed by the current
device certificate. The routing worker receives no enrollment CA private key.

## Transaction and receipt lifecycle

`QueueSoftwareTaskInTransaction` requires the caller's explicit, current catalog
and device authorization. The caller holds its approval/preparation locks and
uses the identity-before-inventory lock order. The registry seals the task and
records its audit within that transaction. The task lifetime is at most one hour
and cannot outlive the source certificate. Only one active software task is
allowed for a device, including uncertain and restart-required work.

The worker calls `HandleSoftwareInTransaction` after locking the current registry
identity and exact single-site Windows inventory scope in the same transaction.
It releases a reply only after commit. Delivery and reporting both fail closed
on an audit failure. Undelivered expiry becomes `expired`; delivered expiry stays
`uncertain` and retains the reservation. Revocation/rotation cancels undelivered
work and preserves uncertainty for delivered work. The full signed envelope and
terminal result are immutable evidence, including against deletion/truncation.

The agent must durably record a unique execution attempt before starting native
work, and durably store its exact signed result before sending it. A missing
result after a retained attempt is possible execution, never permission to retry.
Native exit codes, machine observations and execution state (`not_started`,
`started`, `unknown`) remain separate. A restart code is not installed-state proof.
Uncertain/restart-required tasks need explicit reconciliation; timeouts do not
release them for another installer.

A result includes its original signing certificate and timestamp so an offline
receipt can survive multiple renewals. Every submission also needs a fresh proof
from the current device certificate over the exact result hash. This closes the
interval in which an old broker session can survive certificate rotation.
An exact retry returns the same receipt without another audit or execution.
Historical envelope verification authenticates retained evidence only; it cannot
authorize execution after expiry or under a different certificate generation.

## Verification and remaining integration

Administrative history uses `ReadSoftwareTaskInTransaction`: the caller must
hold its current read rights and commit a read audit in the same transaction.
The result projection contains only original scope/intent identifiers, lifecycle
timestamps and the verified outcome. It excludes envelopes, nonces, private
plans and certificate material. Historical receipt certificates are rechecked
against the original authority at their signing time, even after revocation.
The `reported` task status means a receipt was accepted; observed installation
or removal must come from that receipt's separate outcome.

`CancelSoftwareTaskInTransaction` requires current assignment authorization in
the original site. It locks identity before task, serializing with worker
delivery. It cancels only an undelivered pending task, retains its immutable
history and audits the change before commit. Expired/cancelled retries do not
create another audit. Delivered, uncertain, reported and restart-required work
cannot be cancelled through this API or lose its reservation. Administrative
functions are not exposed as device RPC actions.

Protocol tests cover canonical bounded messages, sender/recipient/context
tampering, separate signature domains, durable results and native outcome rules.
PostgreSQL tests cover delivery, exact retries, audit rollback, foreign scope,
revocation, immutable evidence, retained uncertainty/restart reservations and
current-certificate submission of results from two earlier generations.

The agent and worker consumers must use the matching protocol version. Native
installer staging/execution, explicit console dispatch, result presentation and
reconciliation are consumer integration work; this library alone enables none of
those user-facing actions. Physical Windows package acceptance remains separate
from synthetic protocol and process tests.
