# Expiring NetBird device command protocol

`netbirdcommand` defines version 1 connection commands on
`agent.netbird.command.<device>`. This subject is separate from legacy NetBird
settings messages and is outside the retrying `AGENTS_STREAM` filters. Existing
individual broker policies allow the console to publish it and each endpoint to
subscribe only to its own device suffix. It does not add permissions or change
stream definitions.

Connection and registration commands explicitly include their version, canonical request UUID, device,
organization/site, enrollment mode, certificate hash, reviewed source revision,
operation, management URL, profile, issue time and expiry. Individual targets
require a canonical device UUID and certificate digest. Legacy targets have no
certificate digest and retain the limitations of shared broker credentials.
Version 1 admits `up`, `down` and `switchprofile` and its canonical encoding stays
unchanged. Version 2 exclusively admits `register` with a required, bounded
`setup_key` and empty profile. It carries only the one-off key, never a provider
access token. Version 3 exclusively admits an individually enrolled Unix
`install` command with an exact approved package descriptor, as specified below.
Commands never carry an arbitrary script or executable name.

Before creating a key, registration callers must require a successful correlated
`registration-state` control query. A normal `state` response does not establish
registration support; older agents reject the new control kind. Both return the
same bounded journal state under current identity and certificate lifetime.
Registration uses the existing permanent journal and command subject, so it
cannot overlap connection commands or bypass unresolved work.

The complete version 2 digest includes the registration key. Receipts retain
their version 1 shape and bind that digest and the `register` operation. Neither
the receipt nor the agent journal stores the key. Command/key diagnostic
formatting is redacted; callers must still avoid logging serialized wire bodies.
The protocol does not itself perform provider admission, encrypted result
storage, cleanup or authoritative peer association.

Encoding and decoding reject missing, null, duplicate, case-alias and unknown
fields; invalid types/UTF-8; trailing documents; invalid identifiers; unsafe URLs;
invalid profiles; and messages exceeding 16 KiB. Connection commands carry no
profile; profile switches require a bounded nonempty handle. The management URL
must satisfy the shared HTTPS policy.

Connection and registration lifetime is at most two minutes. Installation has
a separate ten-minute upper bound for native execution. `Executable` additionally
requires the
exact current local identity, an expiry later than the current time and an issue
time no more than five seconds ahead of the local clock. Callers must apply that
check immediately before durable admission, apply the expiry to every execution
step and honor service cancellation. `Valid` and `Decode` validate immutable
syntax only so retained evidence can be inspected after expiry; neither function
alone authorizes execution.

The command digest covers every input using canonical encoding and UTC
timestamps. Receipts contain the request/device/revision/operation, command
digest and one of `completed`, `unconfirmed`, `rejected` or `busy`. A receipt must
pass `Matches` against the exact sent command. Only `completed` is positive
execution evidence. Empty replies, arbitrary error text, nil/negative results
and mismatches must never be converted into success. Receipts contain no profile,
management URL, provider credentials or arbitrary subprocess output.

The codec does not provide persistence, execution authority or retries. Agent
integration must commit a durable attempt before invoking the CLI, retain its
result, prevent concurrent/repeated execution and explicitly handle an attempt
whose result was not persisted. Console integration must retain the actual wire
digest before delivery and verify the correlated receipt. A legacy handler that
returns an empty acknowledgement cannot satisfy this protocol.

Tests cover identity and lifetime boundaries, canonical digests, malformed wire
messages, forbidden operations/targets and round trips; the decoder also provides
a fuzz target. Real device and provider acceptance remain separate checks.

## Live journal control

`agent.netbird.control.<device>` carries a separate ten-second envelope for
read-only `state` and `receipt` queries and explicit `release`. Every request
binds the current local identity, a fresh request UUID and its lifetime. Receipt
and release requests also require the original command UUID and full wire
digest. The release request UUID is the immutable resolution identity.

Responses bind the complete canonical request digest and current identity.
Their nested state and receipt objects obey the same exact field rules as the
envelope. A state is `ready`, `full`, `busy`, `unconfirmed` or `unavailable`.
Readiness includes a revision, remaining capacity (at most 4096 attempts), and
the pending command identity and release eligibility when applicable. Callers
must require a live `ready` result before admitting a new device command.

Receipt queries return only retained `completed` or `unconfirmed` evidence,
optionally including the recorded release UUID. They permit reviewing an older
certificate's command under the current authenticated identity without
reconstructing or delivering that old command. A release response is positive
only for the exact requested resolution UUID; another release is a conflict.
Queries never release a barrier, and a release never turns uncertainty into
success. Missing, blocked, conflicting and unavailable responses carry no
payload. Empty, stale or mismatched replies provide no authority to proceed.

## Explicit withdrawal of an unattempted command

`RecoveryVersion` (control version 2) supports `receipt` and `withdraw` on the
same authenticated control subject. It additionally requires the original
`revision` and `operation`, alongside the command UUID and complete digest.
Version-one control fields, encoding and hashes remain unchanged. A correlated
version-two response is required to establish recovery support; a legacy missing
receipt is insufficient.

A withdrawal must atomically check that no execution attempt exists, persist and
sync a permanent denial for the original UUID, and only then return a `withdrawn`
receipt with its resolution UUID in `release_id`. Its receipt retains the same
bounded metadata shape and never includes a setup key. `withdrawn` is evidence
of durable non-admission, not command completion. Late commands with that UUID
must never execute, including after restart, expiry or certificate renewal.
A same-identity withdrawal replay is idempotent; conflicting reference metadata
or another withdrawal UUID must fail. Existing execution attempts cannot be
converted into withdrawals.

Version-two receipt queries can recover the retained withdrawal and its exact
resolution UUID using current device authority. They remain read-only and can
also return matching completed/unconfirmed execution receipts. A version-one
control response cannot establish withdrawal proof. Current identity, service
cancellation, ten-second expiry, bounded storage and failed-publication rules
continue to apply. Provider cleanup and console resolution admission must be
coordinated separately before further device commands are allowed.

## Exact Unix installation commands

`InstallationVersion` (command version 3) contains the common identity, request
UUID, reviewed revision, `install` operation, issue/expiry times and one nested
`netbirdinstall.Package`. The package's organization must equal the recipient's
organization. The recipient must be individually enrolled with a canonical device
UUID and current certificate hash; shared credentials are never an installation
identity. Management URL, profile and setup key fields are forbidden, including
empty values. Windows installation remains in its separate software protocol.

The nested descriptor is decoded using its own strict bounded codec. Aliases,
duplicates, missing/null fields, unsupported types and unknown fields are rejected
at both levels. Its complete source URL, approval UUID, native target/version,
size and hash enter the canonical command digest. Only explicit `Encode` exposes
the source: incidental JSON serialization of an installation command fails, and
diagnostic formatting conceals it. Earlier command bytes and digests are unchanged.

The package must be prepared and verified separately before a fresh installation
command is admitted. Its ten-minute lifetime bounds native execution; it is not
a download lease or authorization to install a merely matching hash. Before
issuing/admitting it, the console and agent must establish current approval and
revocation state, exact target authority, a matching privately prepared native
package, current certificate lifetime and the common durable operation barrier.
No new subject, stream filter, permission or automatic retry is introduced.

Installation receipts retain the version-one metadata shape and include no
source or package contents. Recovery version 2 can withdraw an unattempted install
or query its retained receipt under current individual identity. Existing explicit
release rules apply to uncertain installation attempts. A release does not prove
installation success or stop an orphaned native process. Unknown operations,
remain invalid in the earlier command grammars. Version four now defines
[exact native removal intent](netbird-removal-commands.md); its native execution
and console lifecycle remain separate integration work.

The protocol and agent journal support this identity. Individually enrolled,
privileged macOS agents with native ACL support can now consume a retained
prepared package under atomic journal revision admission. They invoke the fixed
system installer once and require its exact receipt, complete payload hashes and
protected vendor CLI link before retaining a completed result. Agents without
that native owner reject new commands before persisting an attempt. The console
connection/registration publisher still rejects this version. A separate native
publisher now follows exact package-aware durable admission, fresh authority and
preparation checks. A verified completed receipt opens console admission; lost
results use read-only receipt recovery without redelivery. Separately reviewed
withdrawal/release now require expiring reviews and exact owned proof before the
console barrier opens, preserving the uncertain original result. Automatic
dispatch now binds the native store to joined inventory workers; the
[device lifecycle UI](https://github.com/the-luap/openuem-console/blob/3199b9ba73fd0b990bbd933727a5cdaebf426d77/docs/netbird-installation-ui.md) exposes scoped package review, retained progress
and explicitly reviewed recovery. Console
preparation retains exact attempt/results around one bounded direct RPC after
current approval and both capability checks. Local removal and Linux publisher
trust remain separate.

## Authenticated private package preparation

`PreparationVersion` is a separate version-one protocol on
`agent.netbird.prepare.<device UUID>`. It grants download and native inspection,
never execution. The strict envelope contains the current individual identity,
request UUID, reviewed installation revision, live journal revision, exact private
package descriptor and issue/expiry times. Its maximum lifetime is ten minutes;
the agent independently bounds preparation to five minutes and certificate expiry.
Explicit encoding is required: ordinary JSON and diagnostic formatting cannot
expose the source. Unknown fields, duplicates, aliases, missing/null values and
invalid nested descriptors fail before preparation.

The correlated response contains only version, current identity, request UUID,
complete request hash and `prepared`, `blocked`, `conflict` or `unavailable`.
It contains no source, path or execution receipt. A prepared result is ephemeral:
the same live owner retains the artifact only until its request expires, journal
state changes or the service closes. An exact replay rechecks the file; altered
input cannot inherit it. Restart discards abandoned staged bytes. This protocol
does not retain permanent download attempts or prove current approval revocation.

The individual-only `preparation-state` control explicitly discovers a configured
preparation service and its current journal state. Ordinary and registration state
do not establish this capability. A bare journal or service without native
preparation responds without preparation readiness. Existing broker subject
permissions cover the new exact target; no stream filter or automatic retry is
added. The agent serializes downloads with managed commands and rechecks journal
readiness after inspection. The console must separately retain preparation intent,
authenticate current approval and recipient, and recheck them before fresh native
installation admission. Preparation readiness never advertises an installer.

## Native installation readiness

The individual-only version-one `installation-state` control discovers a live
native installer and its common journal state. Its response must match this exact
kind: ordinary, registration and preparation readiness cannot substitute for it.
A bare journal or a service without a configured native installer responds without
installation readiness. The request adds no broker permission or stream filter.

Readiness is not package admission. A version-three command must consume the same
live preparation UUID, reviewed revision, current individual certificate and exact
package. Its issue time cannot precede that preparation. The service owns the
artifact through native execution and joined cleanup; journal admission checks
that its reviewed journal revision is still ready under the journal mutex.
Completed or uncertain exact replay reads retained evidence without another
preparation or installer invocation. Cleanup failure retains uncertainty. Native
receipt and file evidence do not prove daemon connectivity or provider enrollment.


[Console preparation admission](https://github.com/the-luap/openuem-console/blob/5be886d170478dd199cee99bb69644e96394ebf6/docs/netbird-console-preparation.md) now stores the exact wire version, certificate,
digest and issue/expiry times against its immutable installation request and
encrypted package approval. The attempt and audit commit before one direct RPC;
no database transaction is held across the download. A correlated source-free
result is appended afterwards. Missing or invalid responses retain uncertainty,
and repeats read pending/result evidence without redelivery. Native command
admission must reconstruct and verify that preparation and recheck current
approval, scope, recipient and cancellation before its own durable attempt.
Cancelling the local RPC wait cannot retract preparation already sent to an agent.


[Console native delivery](https://github.com/the-luap/openuem-console/blob/3597328d39f43894b2ad556246ad29532a6345d6/docs/netbird-installation-delivery.md) now reconstructs and verifies the exact retained
preparation, rechecks current authority and persists one fresh version-three
attempt before delivery. Command execution has its own ten-minute maximum and
certificate bound. Native attempts exclude cancellation permanently. A separate
completed receipt opens the common device barrier; the request UUID remains
reserved. Version-two read-only receipt queries under the current certificate
can recover completion after response loss without rewriting the original
uncertain result. Missing, withdrawn or released observations do not substitute
for [reviewed withdrawal/release](https://github.com/the-luap/openuem-console/blob/ab17d569a9a3ea56823b16274503ec0827b6eefc/docs/netbird-installation-resolutions.md). That separate workflow retains a permanent resolution UUID, expiring current-authority
reviews and one immutable attempt per consumed review. Read-only queries recover
lost replies only with exact owned proof. Another control requires a new explicit
review; no native command is retried and release is distinct from completion.

[Console automatic dispatch](https://github.com/the-luap/openuem-console/blob/dc77e7b878432e99296b6b5a7ca8c5ff1fffde4e/docs/netbird-installation-dispatch.md) now processes reviewed native requests without holding a database connection
across preparation or installation. Existing immutable admissions arbitrate
concurrent workers; only successful retained preparation may resume. Uncertain
preparation/native attempts never redeliver automatically. Preflight stops retain
a safe reason and the common barrier until explicit pre-install cancellation.
The protocol and consumer runtime pin are unchanged.

The [console installation pages](https://github.com/the-luap/openuem-console/blob/3199b9ba73fd0b990bbd933727a5cdaebf426d77/docs/netbird-installation-ui.md) now expose scoped approved-package
choice, exact reviewed admission, source-free receipts and history, pre-native
cancellation and expiring withdrawal/release review. Fresh read-only observations
and recovery reconciliation do not send another native command. All 90 new and
2,562 total browser cases pass, along with complete console inventory/audit/view
race suites, real registered HTTP routes and the Linux console build. This UI
integration changes no wire grammar, agent consumer or runtime dependency pin.

[Native removal command and inspection](netbird-removal-commands.md) now bind a
source-free current-state descriptor to version-four `uninstall` and a separate
version-three read-only inspection response. The agent requires its own native
owner and inspected journal revision before admission, retains uncertainty and
withdrawal under the common barrier, and rejects new removal without that owner.
Existing connection/installation publishers cannot deliver this new family.

[Manifest-backed removal recovery](netbird-removal-recovery.md) now adds a
separate version-five command and version-four native inspection. Exact original
uninstall/release evidence and the current journal revision precede new native
admission; retained original results remain immutable. Console lifecycle and
absent-manifest policies remain separate requirements.
