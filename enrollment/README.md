# Individual agent enrollment protocol

[Authenticated Windows software tasks](windows-software.md) describe the separate
signed command, encrypted plan and durable receipt protocol.

This package defines version 1 of the endpoint proof and private message subjects.
It is a shared implementation for the console, agent and worker. The enrollment
service, installer, durable identity storage and broker authentication integration
must use it together; this package alone does not make an existing deployment safe
to expose publicly.

The endpoint generates its RSA certificate key and separate NKey user key locally.
It sends a PKCS#10 request and a broker signature binding that CSR, the limited
invitation, platform, architecture and display name. Validation requires both key
proofs. The server must independently select organization/site, device ID, validity,
certificate subject/extensions and permitted software from its invitation record.
CSR subject names never grant authority. An idempotent retry may recover a result
only for the same `KeyBinding` and authorized request target.

Private keys cannot be JSON-serialized. Persist them with the endpoint's protected
local key storage before requesting issuance, so interrupted enrollment can reuse
them. Never put a private key or long-lived credential into an installer, manifest,
command line or server response.

`NewHTTPClient` claims through the exact HTTPS invitation path at an independently
authorized origin. It owns a bounded transport with verified TLS, no redirects,
no environment proxy and no cookie jar. Optional server roots are copied at
construction; a returned organization authority never becomes HTTPS trust. The
client validates both request proofs before sending, accepts only a bounded,
strict JSON response, and returns generic errors without URLs, tokens or remote
diagnostics. It has a 30-second request bound, 10-second dial/TLS bounds,
25-second response-header limit, 32 KiB response headers and a 96 KiB response body.
At most two connections to the origin are active. The caller cancels active
request contexts and releases idle connections with `CloseIdleConnections`.

`HTTPClient.BootstrapKeys` and `HTTPClient.Configuration` use the same transport
for exact, read-only GET routes at that previously authorized origin. They bound
key documents to 8 KiB and configuration envelopes to 96 KiB, reject invalid JSON,
unexpected content types/encodings and partial or oversized responses, and never
redirect or retry implicitly. Configuration tokens are validated before any HTTP
request. The returned buffers belong to the caller; clear configuration bytes
after verification. Use `bootstrap.ParseOriginKeys` to validate keys obtained from
that authenticated channel and `bootstrap.Verify` with independently provisioned
release keys. Fetching bytes alone does not validate signatures or authorize scope.

`HTTPClient.DownloadPackage` accepts an independently verified release object and
exact platform/architecture. It derives the fixed same-origin path and streams to
caller-owned private staging with the signed size/hash bound. The stream has a
separate 15-minute deadline while sharing the verified transport and two-connection
budget; ordinary claims retain their 30-second limit. Unexpected partial responses,
redirects, encodings, content types, changed lengths or bytes are rejected. Release
expiry is checked again after download. Failures can leave at most the signed size
plus one byte of untrusted output; discard it. Writers must return promptly, since
request cancellation cannot interrupt an arbitrary writer. Native signature checks
and the latest persisted checkpoint remain separate requirements.

`ValidateResponse` requires the local CSR public key, canonical assigned device
ID, positive organization/site IDs, same-origin WSS endpoint, exactly one matching
identity URI and a currently valid client-auth certificate from the returned
identity CA. It rejects other endpoint keys, extra SAN identities, server/CA
privileges, changed expiry, multiple PEM certificates and excessive leaf lifetime.
The CA is trusted for this identity only because the origin was independently
authorized and its HTTPS connection authenticated. This check is not an origin
discovery mechanism and does not attest installation or hardware identity.

`HTTPClient.Claim` does not store or automatically retry keys. A caller must
durably protect pending keys **before the first call**, use those same keys after
an interrupted response, validate approved package/bootstrap state independently,
and commit the verified result before starting the individual agent. The native
Windows/macOS protected-storage and installer integration remains separate work.
Tests exercise real HTTPS/HTTP2, redirects, TLS rejection before credential
transmission, strict response boundaries, cancellation and certificate binding.

`RequestSubject` names the authenticated device and an explicit operation. Workers
must validate that device against active enrollment and check every body resource
against its assigned organization/site. They must also validate `ValidReply` before
responding: a supplied reply subject must not turn a privileged worker's response
into another device's command. A private inbox prefix replaces `_INBOX.>` access.

`DeviceSubjects` permits only that device's requests, commands, inbox and fixed
JetStream consumer. It does not grant consumer creation. The trusted service must
pre-create the consumer with the intended filters; otherwise a device could create
its own-named consumer over someone else's messages. Temporary reply permissions
allow one response to an actual received request, instead of blanket inbox publish
access.

The root package's `ConnectAgent` uses an explicit `wss://.../agent-channel`,
NKey nonce proof and the private inbox prefix. It does not fall back to TCP or
accept credentials in a URL. Discovered broker addresses are ignored so a private
backend address cannot route around the gateway. Reconnection and protocol pings
remain active for the configured gateway endpoint.

Integration tests run a real TLS WebSocket NATS broker and verify individual-key
login, gateway TLS validation, private request/reply, rejection of other device
and administrator subjects, prevention of consumer creation, pre-provisioned
consumer delivery and acknowledgement. They use NATS Server 2.14.6 and Go client
1.53.1. The production gateway route, authentication service, worker binding and
agent release are separate integration requirements still in progress.

`BrokerAuthorizer` implements config-mode NATS auth callout. A protected NKey
service subscribes in an isolated authorization account; configured service NKeys
also enable the nonce challenge in the stock server. The broker's actual nonce is
15 characters in the tested version. The authorizer verifies that proof, binds its
response to the requesting server and fresh connection key, and delegates active
identity lookup plus session recording to one atomic database callback. Device
grants last at most five minutes and never outlive the issued certificate.

The callback must persist the server ID and client ID before returning a grant.
Revocation must commit before sending the recorded sessions to the private system
account's `$SYS.REQ.SERVER.<server-id>.KICK` endpoint. If that path is unavailable,
the broker lease bounds how long an existing connection can remain usable. A
database failure or auth-service outage must deny new connections. Never expose
the callout subscription or system account to the public gateway or ordinary
devices, and never trust a self-signed server JWT received outside that protected
subscription. Separate production configuration must enforce these boundaries.

The real-broker callout test verifies successful individual-key authorization,
unknown/revoked/expired key rejection, recorded-session disconnection, automatic
certificate-expiry disconnection, and denial when the authorizer is unavailable.
Unit tests also verify connection binding, nonce replay rejection and redacted
denials. The [durable registry](registry/README.md) now implements the PostgreSQL
identity/session callback and disconnect outbox, with a combined real-broker test.
It is not yet wired into production services or the released agent.

`StartAgentAuthorizationService` provides the protected queue subscriber with at
most 32 simultaneous lookups, bounded pending messages and cancellation on close.
`DisconnectRevokedSessions` consumes at most 32 persisted sessions per pass and
uses at most eight parallel one-second requests on the separate system connection.
It validates the responding server and handles the already-disconnected response
without discarding retry work. Unattempted sessions take priority over retries so
an older failing batch cannot starve later revocations. Tests exercise the actual
service wrapper against NATS and its lookup/shutdown bounds. Executable service
configuration and deployment wiring remain separate integration work.

`keyfile.Read` bounds credential reads and checks the opened file's permissions.
Unix files must belong to the current user or root and grant no group/other
access. Windows files require a non-null DACL and an owner/allow entries limited
to the service user, Local System and Administrators. A native Windows CI check
exercises a private DACL and rejection of an Everyone-readable file. These checks
do not replace endpoint encryption, atomic installation or protected directory
provisioning, which remain part of the agent/bootstrap integration.

`keyfile.CreateDirectory` creates one private credential directory without creating
parents or changing an existing directory's permissions. Unix uses owner-only
permissions; Windows sets a protected, inheritable DACL for the current service
identity, Local System and Administrators before creation. `CheckDirectory`
validates the opened directory's owner/access controls and rejects a final
symlink or replacement during open. Existing shared directories fail unchanged.
Callers must select parents protected against renames by other users. Individual
files still need `keyfile.Create`/`Read`; the directory does not replace per-file
checks, native encryption, atomic publication or durable enrollment state.

The [FileVault rotation protocol](filevault-rotation.md) adds a distinct encrypted
request/return format, current-certificate signed receipts and a permanent bounded
attempt lifecycle. Its registry is available to trusted server components;
endpoint execution and the console escrow workflow require separate integration.
