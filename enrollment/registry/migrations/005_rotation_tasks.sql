-- Rotation attempts retain immutable context and encrypted receipts. A delivered
-- request that expires is uncertain, because the endpoint may have changed its
-- key before losing connectivity. Expiry never authorizes another execution.
CREATE TABLE uem_agent_rotation_tasks (
 id UUID PRIMARY KEY,
 tenant_id BIGINT NOT NULL,
 site_id BIGINT NOT NULL,
 device_id UUID NOT NULL,
 ordinal SMALLINT NOT NULL CHECK(ordinal BETWEEN 1 AND 128),
 native_id UUID NOT NULL,
 key_id UUID NOT NULL,
 recipient_id UUID NOT NULL,
 certificate_hash TEXT NOT NULL CHECK(certificate_hash ~ '^[a-f0-9]{64}$'),
 nonce_hash TEXT NOT NULL CHECK(nonce_hash ~ '^[a-f0-9]{64}$'),
 context BYTEA NOT NULL CHECK(octet_length(context) BETWEEN 1 AND 4096),
 envelope BYTEA NOT NULL CHECK(octet_length(envelope)<=8192),
 result BYTEA CHECK(octet_length(result)<=8192),
 status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','uncertain','completed','cancelled','expired')),
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 expires_at TIMESTAMPTZ NOT NULL,
 delivered_at TIMESTAMPTZ,
 completed_at TIMESTAMPTZ,
 UNIQUE(device_id,ordinal),
 FOREIGN KEY(tenant_id,site_id,device_id) REFERENCES uem_agent_identities(tenant_id,site_id,id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX uem_agent_rotation_pending ON uem_agent_rotation_tasks(device_id) WHERE status IN ('pending','uncertain');
CREATE INDEX uem_agent_rotation_expiry ON uem_agent_rotation_tasks(expires_at,id) WHERE status IN ('pending','uncertain');

CREATE FUNCTION uem_agent_cancel_rotation_tasks() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.revoked_at IS NOT NULL OR NEW.certificate_expires_at<=clock_timestamp()
    OR NEW.certificate_hash IS DISTINCT FROM OLD.certificate_hash
    OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id OR NEW.site_id IS DISTINCT FROM OLD.site_id THEN
  UPDATE uem_agent_rotation_tasks SET status='cancelled',envelope='\x',completed_at=clock_timestamp()
   WHERE device_id=NEW.id AND status IN ('pending','uncertain');
 END IF;
 RETURN NEW;
END
$$;
CREATE TRIGGER uem_agent_identity_rotation_tasks AFTER UPDATE OF revoked_at,certificate_expires_at,certificate_hash,tenant_id,site_id
 ON uem_agent_identities FOR EACH ROW EXECUTE FUNCTION uem_agent_cancel_rotation_tasks();

CREATE FUNCTION uem_agent_retire_rotation_recipient() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='DELETE' OR NEW.id IS DISTINCT FROM OLD.id OR NEW.public_key IS DISTINCT FROM OLD.public_key
    OR NEW.certificate_hash IS DISTINCT FROM OLD.certificate_hash
    OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id OR NEW.site_id IS DISTINCT FROM OLD.site_id THEN
  UPDATE uem_agent_rotation_tasks SET status='cancelled',envelope='\x',completed_at=clock_timestamp()
   WHERE device_id=OLD.device_id AND status IN ('pending','uncertain');
 END IF;
 RETURN NULL;
END
$$;
CREATE TRIGGER uem_agent_rotation_recipient AFTER UPDATE OR DELETE
 ON uem_agent_recovery_recipients FOR EACH ROW EXECUTE FUNCTION uem_agent_retire_rotation_recipient();
