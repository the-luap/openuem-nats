# Exact native NetBird removal command and inspection

Command version four introduces `uninstall` with an exact inspected native target.
It is separate from connection, registration and installation grammars. This
contract and its agent journal admission are implemented; native package removal
and the reviewed console lifecycle still require their own integration. Merely
upgrading the codec cannot execute a removal or advertise native ownership.

## Inspected target and authority

The source-free `netbirdinstall.Removal` contains schema, platform, architecture,
format, package ID, version and `state_digest`. It accepts only the established
macOS PKG or Linux DEB/RPM identities and architectures. It contains no URL,
approval credential, filesystem path, executable, argument list or provider data.
The descriptor digest includes a removal-specific domain and all its fields.

`state_digest` identifies the native observer's complete inspected ownership and
state. It must bind the exact package receipt and version, protected bundle/file
identities and contents, and applicable service ownership. Periodic inventory,
a package name alone or an old approval hash cannot substitute for this proof.
The native planner must reconstruct the same state immediately before durable
admission and recheck owned objects before each mutation. The wire validator
checks syntax; it cannot establish native ownership by itself.

The command binds that complete descriptor to one permanent UUID, the reviewed
console revision, exact organization/site/device, current individual certificate,
issue time and expiry. Native execution has a maximum ten-minute lifetime. Shared
legacy identities are invalid for removal, receipt recovery and withdrawal.
Version-one/two/three command bytes and existing control digests remain unchanged.
Incidental command JSON refuses to silently discard a native descriptor; use the
explicit command encoder.

## Read-only native inspection

Control version three accepts only `removal-state` under a current individual
identity, with no reference command, revision or mutating operation. Its lifetime
is at most thirty seconds. A response correlates every identity field, UUID and
complete request hash and uses a distinct response grammar:

| Outcome | Evidence |
| --- | --- |
| `ok` | Current non-unavailable journal state and a valid native removal target |
| `absent` | Current non-unavailable journal state and exactly empty target `{}` |
| `unavailable`, `blocked`, `conflict` | Empty journal state and empty target |

These responses carry no execution receipt or release ID. They do not prove that
an installation/removal command completed. An older ordinary journal response
cannot advertise native ownership. Unknown, duplicate, aliased, null, mixed or
partially empty fields fail strict decoding at every level. Use the explicit
response encoder so incidental serialization cannot omit native target evidence.
A journal without a configured native observer reports `unavailable`.

## Durable agent admission and recovery

The agent executor has distinct installation and removal native owners. A missing
removal owner returns `rejected` before creating an attempt and never falls
through to connection execution or an installation planner. A successful planner
holds its native lease through mutation, result verification and joined cleanup.
Only `BeginRemoval` with the matching current ready journal revision can admit a
new removal; ordinary `Begin` cannot bypass the inspection binding.

The shared journal commits an immutable attempt before invoking the native owner.
Native failure, cancellation or failed cleanup retain uncertainty. Replay returns
the original receipt without re-inspection or execution. Any other connection,
registration, installation or removal remains excluded until the original result
or explicit recovery permits it. An orphaned same-boot native attempt cannot be
released. A later boot still requires explicit release before new admission.

Version-two withdrawal binds the original complete command hash, review and
`uninstall` operation to a permanent resolution UUID. It permanently rejects late
original delivery without inventing execution. Current-identity receipt queries
can read the original result after certificate renewal. Installation and removal
proofs cannot substitute for one another; a legacy journal cannot import their
retained attempts or withdrawal records.

## Evidence and remaining work

Owned codec/race tests cover disjoint schemas, lifetime/identity/inspection changes,
strict empty and nested payloads, original wire compatibility and exact recovery
correlation. Descriptor, command and inspection-response fuzz targets exercise
malformed inputs and canonical round trips. Agent filesystem, process-lifecycle
and real-broker tests cover no-owner rejection, journal changes after planning,
completion, response replay, renewed-identity reads, joined cancellation, failed
cleanup, restart exclusion and permanent withdrawal.

The console connection and installation publishers explicitly reject version-four
commands. Its existing direct control publisher transports and verifies the new
read-only inspection grammar; this is not a public removal endpoint. Native
inspection/mutation/result verification, runtime owner binding, console request
storage/dispatch/recovery/UI, Linux individual enrollment/publisher trust and real
package/daemon/device acceptance remain required. No native package was removed
by these fixtures.
