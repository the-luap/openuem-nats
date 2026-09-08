-- Public recipient metadata and end-to-end encrypted validation requests.
-- The routing worker never needs the console master key or recovery plaintext.
CREATE TABLE uem_agent_recovery_recipients (
 device_id UUID PRIMARY KEY,
 tenant_id BIGINT NOT NULL,
 site_id BIGINT NOT NULL,
 id UUID NOT NULL UNIQUE,
 certificate_hash TEXT NOT NULL CHECK(certificate_hash ~ '^[a-f0-9]{64}$'),
 public_key BYTEA NOT NULL CHECK(octet_length(public_key)=32),
 registered_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY(tenant_id,site_id,device_id) REFERENCES uem_agent_identities(tenant_id,site_id,id) ON DELETE CASCADE
);

CREATE TABLE uem_agent_recovery_challenges (
 device_id UUID PRIMARY KEY,
 id UUID NOT NULL UNIQUE,
 certificate_hash TEXT NOT NULL,
 public_key BYTEA NOT NULL CHECK(octet_length(public_key)=32),
 nonce BYTEA NOT NULL CHECK(octet_length(nonce)=32),
 expires_at TIMESTAMPTZ NOT NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 consumed_at TIMESTAMPTZ,
 FOREIGN KEY(device_id) REFERENCES uem_agent_identities(id) ON DELETE CASCADE
);

CREATE TABLE uem_agent_recovery_tasks (
 id UUID PRIMARY KEY,
 tenant_id BIGINT NOT NULL,
 site_id BIGINT NOT NULL,
 device_id UUID NOT NULL,
 native_id UUID NOT NULL,
 key_id UUID NOT NULL,
 -- Recipient IDs are immutable task epochs, not a reference to the mutable
 -- current recipient row. Replacing that row cancels all pending old tasks.
 recipient_id UUID NOT NULL,
 certificate_hash TEXT NOT NULL CHECK(certificate_hash ~ '^[a-f0-9]{64}$'),
 nonce_hash TEXT NOT NULL CHECK(nonce_hash ~ '^[a-f0-9]{64}$'),
 envelope BYTEA NOT NULL CHECK(octet_length(envelope)<=8192),
 result BYTEA CHECK(octet_length(result)<=8192),
 status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','completed','cancelled','expired')),
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 expires_at TIMESTAMPTZ NOT NULL,
 completed_at TIMESTAMPTZ,
 delivered_at TIMESTAMPTZ,
 UNIQUE(tenant_id,site_id,device_id,id),
 FOREIGN KEY(tenant_id,site_id,device_id) REFERENCES uem_agent_identities(tenant_id,site_id,id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX uem_agent_recovery_pending ON uem_agent_recovery_tasks(device_id) WHERE status='pending';
CREATE INDEX uem_agent_recovery_expiry ON uem_agent_recovery_tasks(expires_at) WHERE status='pending';

CREATE FUNCTION uem_agent_cancel_recovery_tasks() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.revoked_at IS NOT NULL OR NEW.certificate_expires_at<=clock_timestamp()
    OR NEW.certificate_hash IS DISTINCT FROM OLD.certificate_hash
    OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id OR NEW.site_id IS DISTINCT FROM OLD.site_id THEN
  UPDATE uem_agent_recovery_tasks SET status='cancelled',envelope='\x',completed_at=clock_timestamp()
   WHERE device_id=NEW.id AND status='pending';
  DELETE FROM uem_agent_recovery_challenges WHERE device_id=NEW.id;
 END IF;
 RETURN NEW;
END
$$;
CREATE TRIGGER uem_agent_identity_recovery_tasks AFTER UPDATE OF revoked_at,certificate_expires_at,certificate_hash,tenant_id,site_id
 ON uem_agent_identities FOR EACH ROW EXECUTE FUNCTION uem_agent_cancel_recovery_tasks();
