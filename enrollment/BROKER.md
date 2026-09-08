# Individual broker configuration and command provisioning

`BrokerConfiguration.Render` generates a stock NATS 2.14.6 configuration for a
dedicated individual-agent broker. It takes only public service NKeys and local
TLS/storage paths. Generating/protecting the service seeds, installing the TLS
files and starting the components are separate deployment responsibilities.

The configuration defines `UEM_AUTH`, `UEM_SYSTEM` and `UEM_DEVICES`. Authorization,
revocation, worker, console and command provisioning use different user NKeys.
Individual devices are dynamically authorized through the PostgreSQL registry;
legacy shared agent credentials must never be added to this broker.

The config-mode `auth_users` field lists the static trusted services that bypass
the device callout. This does not grant access to the authorization account: each
service still proves possession of its NKey and receives only its configured
account/subject permissions. Without this bypass, static users in the delegated
device account are also sent through device authorization. Device NKeys never
appear in the bypass list.

The worker subscribes only to versioned agent requests and can send one temporary
reply. The console publishes commands but cannot alter consumers. The provisioner
can create/read the fixed command stream and create/read/delete its consumers but
cannot publish commands. The revocation user can request only client kicks. The
authorization user can receive only callouts and send one temporary reply.

Native service connections verify TLS and NKey proof. The WSS listener additionally
requires a certificate from the dedicated gateway trust bundle. Both listeners
must remain private; the public gateway exposes only `/agent-channel`. No monitoring
port, clustering, leaf-node listener or public client listener is enabled by this
renderer. Multi-node deployment is not implemented by this single-node reference.

`EnsureAgentCommandStream` creates a file-backed, seven-day work queue bounded to
5 GiB, 64 KiB per message and 64 pending messages per subject. Saturation rejects new
commands instead of silently discarding earlier work. Only enable/disable/report,
updater update/rollback and uninstall commands are durable; no private-key delivery
subject is present.

`EnsureAgentCommandConsumer` creates a fixed consumer for one canonical device ID.
It uses explicit acknowledgments, one pending command, five delivery attempts and
bounded pull requests. Call it after durable identity issuance and before the
endpoint is told it can connect; retry a broker failure without issuing a different
identity. `ReconcileAgentCommandConsumers` performs bounded creation/deletion from
the registry's durable work queue, including revocation. Its executable service
integration and claim-response coordination are still required.

Agents use `OpenAgentCommandConsumer`, which reads only their exact consumer and
validates its stream/name, device filters, acknowledgment/delivery policy and pull
bounds. Missing or conflicting configuration returns an error without a creation,
update or stream-management request. Retry after the trusted service reconciles
the consumer. Pull one message at a time with an expiry no longer than
30 seconds. A command exceeding five delivery attempts remains visible for
operator investigation; this package does not silently acknowledge failed work.

Both provisioning functions are idempotent for matching configuration and reject
conflicting existing definitions. They do not silently rewrite a legacy stream or
widen filters. A dedicated account avoids taking over the upstream stream that
shares the `AGENTS_STREAM` name.

The race-tested integration fixture renders the actual configuration file, loads
it with the stock NATS parser and runs TLS/WSS, service isolation, nonce proof,
individual queued delivery and filter-conflict tests. It also checks that public
service keys without valid signatures cannot use the static bypass. This is
automated protocol evidence, not production firewall or physical endpoint acceptance.

Registry migration `002_command_consumers.sql` atomically records desired consumer
state on identity issuance, revocation, renewal and site ownership changes. It
backfills existing identities and keeps older trusted registry writers compatible
through triggers. Polling detects certificate expiry as time passes. Work is leased
for 30 seconds, processed in batches of 32 with at most eight simultaneous broker
operations, and acknowledged only for the leased revision and desired state. A stale
completion requests another check of the current state. Hourly reconciliation
recovers broker data loss or a process crash after a broker operation but before
database acknowledgment. New or never-attempted work takes priority over retries.

Combined PostgreSQL/NATS tests cover uncertain completion, process-state recreation,
idempotent retry, revocation deletion and repeated deletion of an absent consumer.
Database race tests cover leased work, stale acknowledgments, site moves and expiry.
