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
access. Broker integration tests must verify these policies with a real NATS server.
