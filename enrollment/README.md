# Individual agent enrollment protocol

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
