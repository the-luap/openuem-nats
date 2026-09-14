# NetBird provider peer evidence

`netbirdapi.ManagedKeyPeer` reads the configured provider's bounded audit feed
and selects positive `peer.setupkey.add` evidence by the exact retained setup-key
ID in `initiator_id`. The event's `target_id` identifies the provider peer. It
does not select by name, IP, free-form event metadata or a reported public key.

This contract was checked against NetBird source revision
[`791401060d2b95e5f51e3439c0649729132f571e`](https://github.com/netbirdio/netbird/tree/791401060d2b95e5f51e3439c0649729132f571e):

- [Peer registration](https://github.com/netbirdio/netbird/blob/791401060d2b95e5f51e3439c0649729132f571e/management/server/peer.go#L710)
  assigns the setup-key ID as initiator and the created peer ID as target.
- [Activity codes](https://github.com/netbirdio/netbird/blob/791401060d2b95e5f51e3439c0649729132f571e/management/server/activity/codes.go#L293)
  identify registration with a setup key as `peer.setupkey.add`.
- [The event handler](https://github.com/netbirdio/netbird/blob/791401060d2b95e5f51e3439c0649729132f571e/management/server/http/handlers/events/events_handler.go)
  projects these IDs into the public response. The documented endpoint is
  [GET /api/events/audit](https://docs.netbird.io/api/resources/events).
- [The event store wrapper](https://github.com/netbirdio/netbird/blob/791401060d2b95e5f51e3439c0649729132f571e/management/server/event.go)
  can disable logging and limits reads to the most recent 10,000 events. Missing
  evidence therefore never proves that registration did not happen.

The ordinary [peer API](https://docs.netbird.io/api/resources/peers) does not
expose a WireGuard key for direct identity comparison. `ObserveManagedPeer`
reads one exact provider ID and returns its creation time and bounded display
metadata. It establishes absence only on a successful exact-ID 404. These reads
do not prove local WireGuard identity, device execution, current connectivity or
group membership.

Both functions reuse the HTTPS-only, bounded, non-redirecting transport. They
never mutate the provider or fall back to name/IP lookup. The audit reader limits
the response to 1 MiB and 10,000 events, rejects duplicate event IDs and ambiguous
matching events, and requires an explicit bounded time interval. It accepts
canonical numeric and string event IDs. Unknown nonconflicting response fields
remain compatible; duplicate fields and case aliases fail closed. Only relevant
event IDs and time are returned, excluding user emails and free-form metadata.

The console must separately check current authority, retained one-off key policy,
original delivery admission and cleanup evidence before associating a peer with a
registration. Provider creation time and event time must fit that retained
registration, and any association needs its own immutable storage and audit.
This library alone does not authorize peer deletion.

Owned TLS tests cover correct origin/prefix/authority, numeric event IDs, missing
and unrelated evidence, time limits, duplicate/ambiguous evidence, strict JSON,
response bounds, exact peer IDs, absent objects, redirects and provider errors.
The complete `netbirdapi` race suite passes in 2.117 seconds. Tests do not contact
a real provider or invoke an installed NetBird client.
