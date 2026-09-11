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

## Verification and integration boundary

Tests use real command certificates and device signatures to cover altered
original contexts, hashes, generation/scope/lifetime, cross-domain signatures,
expired commands, renewed certificate submission, mismatched signed transcripts,
nonce proof, contradictory boot/outcome states and definite removal/install drift.
Bounded canonical codecs reject unknown/duplicate fields, alternate encodings and
oversized messages. The fuzz target checks canonical round trips and the minimum
evidence needed for an outcome to be eligible for reservation release.

Local validation passed the full repository race suite against an owned isolated
PostgreSQL instance (registry: 64.981 seconds), the focused final nonce-binding
race check, Windows amd64 build and enrollment vet. The bounded reconciliation
fuzz run passed 195,387 inputs in 15.740 seconds. Native CI separately executes
the same protocol tests and a bounded fuzz run; its definition alone is not proof
that the remote checks passed.

This change provides the wire types and verification primitives only. It adds no
device RPC action, capability advertisement, database release transition, native
observation consumer or console reconciliation button. Those integrations must
preserve the original execution receipt, retain a separate immutable observation,
and apply all current identity/authorization checks before release. Existing
uncertain/restart-required tasks remain reserved. Physical reboot, hibernate,
offline and package acceptance remain separate requirements.
