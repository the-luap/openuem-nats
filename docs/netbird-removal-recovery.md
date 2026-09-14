# Explicit manifest-backed NetBird removal recovery

Command version five and control version four define a separate continuation of
an interrupted native removal. They do not reinterpret an original `uninstall`
receipt, automatically retry delivery, or allow cleanup based on missing files.
Existing command/control encodings and their hashes remain unchanged.

## Original evidence and current review

`RemovalRecoveryReference` contains the original uninstall request UUID, exact
command hash, original console review revision, separately confirmed release UUID
and original macOS removal descriptor. Syntax alone cannot prove ownership:
the agent journal must match the original attempt and release, and the protected
original-UUID manifest must match the original descriptor.

`RemovalRecovery` adds an explicit mode, current journal revision and current
native-state fingerprint. Only `manifest` mode is accepted. Missing-manifest,
empty-stage and replacement-package policies cannot be inferred from this mode.
The current fingerprint binds remaining original files and receipt objects,
typed system-job state and exact original/relocated process ownership.

Three revisions have distinct purposes:

| Field | Binding |
| --- | --- |
| `original.revision` | Immutable original console review |
| `recovery.journal_revision` | Current ready journal from native inspection |
| Command `revision` | Current console review for the new recovery request |

## Inspection

Control version four accepts only `removal-recovery-state`, with a current
individual identity, fresh request UUID, original reference and at most 45
seconds of validity. It has no legacy reference/hash/operation fields. Exact
request bytes bind the response's request hash and current certificate.

An `ok` response includes a valid ready journal and the recovery descriptor. Its
original reference must equal the request's reference; its journal revision must
equal the returned state revision. `missing`, `blocked`, `conflict` and
`unavailable` require empty state and recovery evidence. There is no `absent`
success, original execution receipt or new release proof in this grammar.

## Separate execution

Version-five `recover-removal` carries the current individual identity, a new
request UUID, current console revision, recovery descriptor and at most ten
minutes of validity. Its request UUID must differ from the original uninstall
and original release UUIDs. Connection configuration, setup keys, package
sources, fresh-removal descriptors and implicit alternate modes are invalid.

The agent checks retained exact results before acquiring any native owner. For a
new attempt it requires the exact released unconfirmed original uninstall,
current ready journal and matching reviewed native state. Admission atomically
checks the original proof and current journal revision again before creating the
new durable start. Mutation follows admission; native execution and cleanup join
before the separate completed/unconfirmed result. Original evidence is immutable.

Recovery receipts use the existing correlated receipt grammar with operation
`recover-removal`. Exact read-only receipt recovery and explicit withdrawal use
control version two; release uses the existing reviewed release grammar. All
native evidence requires individual identities. The common journal barrier
continues to exclude work until the latest uncertainty is explicitly resolved.

## Encoding and validation

Only explicit codecs serialize recovery references, descriptors, commands and
native control messages. Incidental JSON refuses to silently omit their fields.
Bounded exact-key parsing rejects unknown, aliased, duplicate, missing and null
fields at every nested level, trailing values and noncanonical empty evidence.
Older versions reject nonzero recovery fields.

Race tests cover reference/release/review/identity correlation, exact expiry,
mixed operation rejection, old-grammar isolation and nested ambiguity. A seeded
command/control/response fuzz target checks accepted-message round trips.
This protocol does not itself provide a console request store, authorization UI
or a policy for absent manifests.
