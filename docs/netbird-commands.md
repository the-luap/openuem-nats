# Expiring NetBird device command protocol

`netbirdcommand` defines version 1 connection commands on
`agent.netbird.command.<device>`. This subject is separate from legacy NetBird
settings messages and is outside the retrying `AGENTS_STREAM` filters. Existing
individual broker policies allow the console to publish it and each endpoint to
subscribe only to its own device suffix. It does not add permissions or change
stream definitions.

Every command explicitly includes its version, canonical request UUID, device,
organization/site, enrollment mode, certificate hash, reviewed source revision,
operation, management URL, profile, issue time and expiry. Individual targets
require a canonical device UUID and certificate digest. Legacy targets have no
certificate digest and retain the limitations of shared broker credentials.
Only `up`, `down` and `switchprofile` are admitted. Provider registration keys and
installation scripts are not part of this protocol.

Encoding and decoding reject missing, null, duplicate, case-alias and unknown
fields; invalid types/UTF-8; trailing documents; invalid identifiers; unsafe URLs;
invalid profiles; and messages exceeding 16 KiB. Connection commands carry no
profile; profile switches require a bounded nonempty handle. The management URL
must satisfy the shared HTTPS policy.

Command lifetime is at most two minutes. `Executable` additionally requires the
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
