# Signed Windows software reconciliation evidence

The reconciliation codec is separate from the existing executable software task
format. It authorizes a read-only observation of one retained task after explicit
operator review. It contains no package URL, installer arguments, MSI properties,
encrypted executable plan or recipient key. It cannot authorize an installer.

`SoftwareReconciliationVersion` is 1 and the signature and certificate-URI domains
are distinct from software installation, software receipt submission and FileVault
recovery. Existing executable tasks and their version 1 receipts remain unchanged.

## Task and evidence binding

The task binds a fresh reconciliation ID, current certificate generation, original
software context and envelope hash, and a lifetime of at most one hour. Permanent
device, organization and site ownership must agree with the original context.
The pinned enrollment CA issues an ephemeral Ed25519 command certificate limited
to this reconciliation and lifetime. The signing key is discarded after use.

Current verification authorizes a new observation. Historical verification checks
retained evidence only. An expired reconciliation cannot authorize another read,
and a command for an earlier certificate generation cannot be rebound to a new
one. An offline signed result can still be submitted after renewal with a fresh
proof from the current device certificate. That proof lasts at most five minutes
and binds the exact reconciliation receipt hash in its own signature domain.

`VerifySoftwareReconciliationEvidence` verifies the original executable envelope,
reconciliation signature, exact context/hash linkage, result certificate chain
at its signing time, result signature and original protected nonce. It also
requires the original nonce hash retained by the registry. A complete transaction
must additionally verify `VerifySoftwareReconciliationSubmission` against the
current locked identity, current authorization and original-scope reservation.
An independently valid signature on a mismatched original task is insufficient.

## Boot and observation semantics

`SoftwareBootSession` contains the loader boot sequence and the System process
creation value. A later session requires valid evidence at both ends, a strictly
greater loader sequence and a different System creation value. A service restart,
sequence-only hibernation/resume change, rollback, wrap or missing original boot
proof cannot establish a later kernel session. Creation values need not increase,
since the wall clock may move backward across a real boot.

The agent's [native boot journal](https://github.com/the-luap/openuem-agent/blob/15044d8c1e0d2d17452d0b6321d9a1ae62953021/docs/windows-software-boot-evidence.md)
provides the admission evidence. Existing intents without that evidence must not
invent it during reconciliation. These are signed endpoint assertions; they are
not hardware attestation or proof against a compromised privileged endpoint.

| State | Required evidence | Reservation release eligible |
| --- | --- | --- |
| `observed` | Later kernel session, original nonce, exact requested installed version or observed removal | Yes |
| `drifted` | Later kernel session, original nonce, definite state differing from the requested outcome | Yes |
| `unknown` | Later kernel session and original nonce, but no definite package observation | No |
| `waiting_for_boot` | Valid admission/current evidence that does not establish a later session; no package observation | No |
| `unavailable` | No usable original journal or boot proof; no nonce, boot values or package observation asserted | No |

`AllowsRelease` validates only this outcome shape. It never authenticates a
receipt, changes a reservation or replaces transaction authorization. Even a
definite drift outcome requires an explicit later install/removal request before
another execution. Neither a restart exit code nor a service restart is success.

An unavailable result may be signed without the original nonce so that a missing
journal can be reported truthfully. It must remain incapable of releasing the
reservation. All other states require the original 32-byte nonce; definite states
also require later-boot proof and a non-unknown exact observation. The result must
be signed within the reconciliation lifetime, then retained unchanged for retry.

## Registry transition and private RPC

Migration 013 adds immutable reconciliation intent/result rows and a separate
release reference on the original software task. It preserves every existing
executable envelope, receipt, outcome, status and timestamp. The active-task
constraint excludes an original task only after it has a retained release
reference; the database guard requires an accepted definite observation in the
same organization, site, device and original-task scope. An unknown, waiting or
unavailable observation cannot release a reservation, even through a direct SQL
update. A release reference cannot be reassigned or erased.

`QueueSoftwareReconciliationInTransaction` requires current explicit assignment
permission and the caller's locked Windows inventory/capability evidence. It
locks current identity before original task and reconciliation rows. Only delivered
uncertain/restart-required originals can be reviewed; review alone changes no
execution state. One active observation is allowed per original task. Identical
retries retain the original signed intent and audit; another active request is
rejected. The review deadline must be more than one minute away, at most one hour
away, and within the current device certificate lifetime.

`SoftwareReconciliationRequest` has only `poll` and `result` actions. Its separate
protocol discriminator is intended for the existing private `software` subject;
the executable software decoder rejects it. The routing worker must explicitly
select the matching decoder and retain its current identity/inventory locks.
The optional configuration field `software_reconciliation_version` negotiates
server support independently of executable software delivery. A worker advertises
it only on an individually authenticated Windows configuration path after the
reconciliation schema is ready. A legacy or Mac configuration leaves it zero.
`HandleSoftwareReconciliationInTransaction` checks the subject-bound device,
current authority, task generation, complete retained transcript and fresh current
certificate proof. Delivery, receipt and any original reservation release are
audited in the same transaction. A worker must send the reply only after commit.

Expiration of a read-only observation never releases the original execution.
A receipt signed before its deadline can arrive after expiration and certificate
renewal. An accepted definite late receipt cancels a subsequent undelivered
observation. An original execution receipt that arrives later is retained without
changing the established release or another task's reservation. No reconciliation
runs or automatically retries an installer.

`ReadSoftwareReconciliationInTransaction` returns verified safe observation history
under the caller's original-scope read rights and audit. The original task projection
keeps its execution outcome and adds the separate reconciliation ID/time. Reading a
released original re-verifies its referenced signed observation. Revocation preserves
history and cancels undelivered generation-bound observation tasks. Administrative
cancellation applies only before delivery and cannot release executable work.

## Verification and integration boundary

Tests use real command certificates and device signatures to cover altered
original contexts, hashes, generation/scope/lifetime, cross-domain signatures,
expired commands, renewed certificate submission, mismatched signed transcripts,
nonce proof, contradictory boot/outcome states and definite removal/install drift.
Bounded canonical codecs reject unknown/duplicate fields, alternate encodings and
oversized messages. The fuzz target checks canonical round trips and the minimum
evidence needed for an outcome to be eligible for reservation release.

The standalone signature codec passed [native CI](https://github.com/the-luap/openuem-nats/actions/runs/34592854588)
at revision `39eae9b946e31dad954ddbf32d983fb4872744b2`. Local validation of the
subsequent registry/RPC integration passed the full repository race suite against
an owned isolated PostgreSQL instance (registry: 90.171 seconds), enrollment and
registry vet, and Windows amd64/Linux arm64 builds. Its expanded bounded RPC fuzz
run passed 264,777 inputs in 16.305 seconds. The workflow includes the new tests;
its definition alone is not proof that a remote integration run passed.

The registry tests cover all five outcomes for retained uncertainty, restart-required
receipts and missing original receipts; queue/delivery/report/release audit rollback;
concurrent exact queue and receipt retries; foreign scope, wrong nonce, immutable
history, cancellation, two real certificate renewals, historical proof after revocation,
late original receipts, corrupted release evidence and migration of existing retained
restart uncertainty. A short-lived signed fixture exercises actual deadline expiry,
offline receipt recovery and cancellation of a superseded pending observation.

Worker routing, agent capability advertisement, protected native reconciliation
journals/observation execution and the explicit console review/history UI still need
integration. This library exposes no user-facing reconciliation action on its own.
Physical reboot, hibernate, offline and package acceptance remain separate requirements.
