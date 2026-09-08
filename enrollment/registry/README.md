# Durable individual-agent registry

This trusted-server package owns additive PostgreSQL tables for organization
signing authorities, limited invitations, individual identities, broker sessions
and audit events. It requires the existing OpenUEM `tenants` and `sites` tables.
It is a server implementation component; console routes, worker integration,
endpoint storage, installers and production deployment are still separate work.

`EnsureAuthority` creates an organization CA automatically or imports an explicitly
supplied enterprise signing CA/key. CA keys are encrypted with AES-GCM, a domain
separated master key and organization-bound authenticated data. Repeated setup
preserves the original CA and public origin. Changing or rotating an established
authority is intentionally a separate lifecycle operation, not a setup retry.
The master key must be backed up separately from the database.

`Invite` fixes organization, site, platform, architecture, expiry (at most seven
days) and use count (1–1000). Only a digest of the random 256-bit invitation is
stored. `Claim` verifies the shared CSR and NKey proof before entering the issuance
transaction. It locks the invitation, validates its current scope and issues a
server-named client-auth certificate for the endpoint's RSA key. The certificate
lasts at most 90 days and cannot outlive its CA. Requested CSR subjects, SANs and
extensions confer no authority. The server generates no endpoint private key.

Concurrent retries with the same keys return the same public identity and
certificate without another use. A key already registered under any invitation
cannot create a second identity. Expired/revoked invitations stop all further
claims and retries. Revoking an invitation does not revoke previously issued
identities; those have a separate explicit action. Production HTTP handlers must
apply rate limits and return redacted errors, and console callers must enforce
action permissions before using the store.

`InviteInTransaction` and `ClaimInTransaction` compose these operations with a
trusted caller's related state, such as the console's approved installer binding.
Use a transaction from the same registry database, roll it back on any error, and
commit before exposing a returned invitation token or issued identity. These
methods never commit for the caller. Claim still verifies both endpoint key proofs;
the ordinary `Claim` API retains its validation-before-transaction behavior.
Rollback removes invitation/identity changes, use-count increments, success audit
events and the triggered command-consumer work together. Keep transaction lock
order consistent in all callers and avoid network operations while holding locks.

`AccessStore` needs no encryption master key or CA signing key. It resolves active
device scope for workers and provides the broker authorizer's database callback.
The callback checks identity and records the actual server/client session in one
transaction, using the same identity lock as revocation. Revocation commits both
the revoked state and pending disconnect records atomically. The disconnect
worker reads bounded, five-second leased batches and kicks those exact clients
through a private NATS system account. Work remains retryable until the broker
lease expires, including after a process restart or an early kick that raced with
completion of authentication. Expired session records can be pruned separately.

The application must prove TLS key possession before calling
`AuthenticateCertificate`; a copied public certificate is insufficient. A trusted
gateway must validate its own mutual-TLS boundary before forwarding a device leaf.
Worker requests still require scoped subject parsing, a private reply prefix and
validation of body device/resource IDs against the returned database scope.

Run the PostgreSQL/race suite against a disposable test database:

```sh
AGENT_ENROLLMENT_TEST_DATABASE_URL='<isolated PostgreSQL DSN>' go test -race -count=1 ./...
```

Each registry test creates and drops a unique schema. Tests prove concurrent use
limits, idempotent recovery after restart, CA-key encryption and organization
binding, rejection of changed targets/site ownership and reused keys, expiration,
scoped revocation, concurrent authorization/revocation, and durable disconnect
retries. A combined real NATS/PostgreSQL test authorizes an issued identity, records
its live session, recreates the access component, then kicks the correct connection
and rejects reconnection after revocation. Tests do not install a Windows or Mac
agent and are not hardware or production acceptance evidence.

Migration 005 and `AccessStore` provide the [FileVault rotation registry](../filevault-rotation.md).
Delivered expiry retains uncertainty, late authenticated key receipts remain
recoverable, and immutable per-identity ordinals prevent automatic attempt reuse.
Signed uncertainty continues to block mutation until independent console recovery.
The worker does not receive plaintext keys or the console return private key.
