# Independent current removal absence protocol

Command version six, `verify-removal-absence`, records a new verification of the
supported current macOS package layout. It does not repeat an uninstall or
manifest continuation and cannot change the meaning of an earlier receipt.

The explicit `absence` descriptor contains an original reference with only its
uninstall request UUID, command hash, console revision and owned release UUID.
It contains no original native package descriptor or manifest. The reference
requires journal verification of the original released unconfirmed attempt;
its syntax alone proves no ownership.

The descriptor also contains the fixed `macos-official-pkg-v1` profile, the
current ready-journal revision and current native absence fingerprint. The
command's separate console revision binds its current review. A new request UUID
must differ from both original UUIDs. Individual enrollment, an exact current
certificate, a valid scoped identity and a lifetime of at most two minutes are
mandatory. Connection credentials, installation packages and removal/recovery
descriptors are forbidden.

Control version five, `removal-absence-state`, requests a fresh read-only review
of the same original reference, with a maximum lifetime of 45 seconds. An `ok`
response contains the exact original reference, supported profile and current
native fingerprint alongside a ready journal whose revision matches the
descriptor. `missing`, `unavailable`, `blocked` and `conflict` carry no positive
evidence. Existing native inspection versions cannot advertise this capability.

Successful command receipts mean that the **new current-absence verification**
completed. They never assert the success of the referenced original uninstall.
Receipts and exact version-two observation/withdrawal controls bind the new
operation, command hash, revision and UUID; legacy identities cannot acquire
these controls. The existing explicit release grammar retains its owned
unconfirmed receipt semantics.

All envelopes and nested evidence use exact required fields. Unknown, duplicate,
case-aliased, missing or null fields, oversized messages and trailing documents
are rejected. Old command and inspection grammars forbid hidden absence data.
Incidental JSON serialization cannot drop or expose the new intent; callers use
the explicit codecs. Version-five manifest continuation remains manifest-only.

## Required runtime integration

An agent must bracket native review and read-only acquisition with identical
original-release and current-journal checks. It must durably admit a new attempt
before running the acquired verification, join close before recording its result,
and serve exact replay without another native query. No old UUID may be rerun;
neither positive absence nor a release changes an original uncertain result.

A console must retain current scoped authority, original owned proof, the exact
new review and immutable delivery intent. Admission of this new operation must
share device/UUID exclusion with all other NetBird command families. A review
response is not an execution receipt and never authorizes stage cleanup.

Codec, receipt, legacy/mutating separation and strict nested-decoder tests pass
under the race detector. Fuzzing checks stable decode/encode behavior across
commands, inspection requests and responses. Agent and console runtime wiring
are separate integration work; this module does not dispatch native commands.
