# Independent reviewed removal scaffold cleanup

Command version seven, `cleanup-removal-stage`, describes a new explicitly
reviewed cleanup of an interrupted uninstall's current private scaffold. It is
separate from version-five manifest continuation and version-six read-only
absence verification. It cannot become a fallback or a replay of either.

## Immutable command

The command requires current individual identity and certificate, a new UUID,
console review revision, exact original reference and current native/journal
review. The original reference contains only uninstall UUID, command hash,
revision and owned release UUID. The new UUID differs from both original UUIDs.
It carries no inferred package descriptor, path, native manifest, connection
profile or credential.

The explicit descriptor contains:

| Field | Meaning |
| --- | --- |
| `original` | Exact immutable uninstall and separate owned release reference |
| `profile` | Only `macos-official-pkg-stage-v1` |
| `journal_revision` | Current ready journal independently of the console revision |
| `state_digest` | Current protected ancestry, scaffold and incomplete metadata fingerprint |
| `directory_count` | Exactly reviewed current directory count, from 1 through 7 |
| `manifest_present` | Whether the reviewed incomplete metadata file exists |
| `manifest_bytes` | Exact reviewed byte count, from 0 through 2 MiB; missing implies zero |

Command lifetime is at most five minutes. The native owner separately compares
all displayed scope fields and the current fingerprint before acquiring objects.
A syntactically valid command is not proof of native or journal ownership. The
agent must prove the original owned unconfirmed release and current ready state,
prepare read-only, admit a distinct durable attempt, then run and join the owner
before recording its new result. Unknown payloads, complete usable manifests,
foreign stages or current runtime/receipt conflicts prohibit native cleanup.

The independent receipt retains the exact operation, new request, revision and
command hash for completed, unconfirmed, busy, rejected and withdrawn outcomes.
Completion never changes the original uninstall's retained uncertain outcome.
An already missing stage needs the separate absence workflow, not an implied
successful cleanup or an automatic replay.

## Native inspection

Control version six, `removal-stage-cleanup-state`, is a 45-second read-only
inspection under current individual identity, containing only the exact original
reference. Its response is correlated to the complete request digest. `ok`
requires a ready journal and matching original reference, profile, journal
revision and bounded cleanup summary. Missing, blocked, conflicting and
unavailable responses carry empty evidence. No inspection receipt is execution
proof and no inspection clears a journal barrier.

The service must expose inspection and its complete acquired cleanup owner as a
pair. Bare journal state cannot advertise native cleanup capability. Current
identity, deadline, original release and journal state must bracket both native
inspection and acquisition; drift discards the review before mutation.

Version-two retained receipt and permanent withdrawal controls bind this exact
new operation and require individual identity. An owned version-one release
retains the uncertainty of an exact unconfirmed entry after local execution has ended. Controls cannot
rewrite cleanup evidence as absence verification or original removal success.

## Wire and compatibility

Only the explicit command, descriptor, reference and control codecs serialize
cleanup intent. Incidental JSON is refused; diagnostics omit its evidence.
Every required nested summary field is mandatory, including false and zero
values. Duplicate, aliased, missing, null, unexpected and incorrectly typed
fields are rejected. The bounded explicit wire keys are `stage_cleanup` for a
command/response and `original` for inspection. Older command and inspection
versions reject hidden cleanup fields and retain their existing wire bytes.

The full command and package protocol race suites passed in 1.598 and 1.664
seconds. Owned tests cover exact summaries and receipts, original/individual
identity, scope, times, all native inspection outcomes, cross-operation refusal,
old grammar compatibility, required nested fields and receipt/withdrawal
correlation. The cleanup fuzz target passed 216,584 inputs in 11.441 seconds.
The protocol does not itself install a remote handler or console action.


The [native owner and agent journal/service integration](https://github.com/the-luap/openuem-agent/blob/66404dc8faf209ef091c2fc696e710e2ffb8692a/docs/netbird-removal-stage-cleanup.md)
now implement these admission rules, paired capability configuration, summary
binding, one durable attempt, joined completion and exact replay. Full native,
journal and command races, isolated Linux suites and all three platform builds
passed. The console has a dedicated one-attempt publisher with exact response
validation; its complete scoped cleanup admission and operator workflow remain
open. Consumers pin runtime commit `8685f28fa959d05a0c9bd300dc2c79c5195bbd4b`;
subsequent documentation updates do not change that module pin.
