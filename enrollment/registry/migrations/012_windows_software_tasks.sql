-- Dedicated recipients and signed, encrypted commands for approved Windows
-- software. FileVault keys/proofs/subjects cannot authorize this operation.
CREATE TABLE uem_agent_software_recipients (
 device_id UUID PRIMARY KEY,
 tenant_id BIGINT NOT NULL,
 site_id BIGINT NOT NULL,
 id UUID NOT NULL UNIQUE,
 certificate_hash TEXT NOT NULL CHECK(certificate_hash ~ '^[a-f0-9]{64}$'),
 public_key BYTEA NOT NULL CHECK(octet_length(public_key)=32),
 registered_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY(tenant_id,site_id,device_id) REFERENCES uem_agent_identities(tenant_id,site_id,id) ON DELETE RESTRICT
);
CREATE TABLE uem_agent_software_challenges (
 device_id UUID PRIMARY KEY REFERENCES uem_agent_identities(id) ON DELETE RESTRICT,
 id UUID NOT NULL UNIQUE,
 certificate_hash TEXT NOT NULL,
 public_key BYTEA NOT NULL CHECK(octet_length(public_key)=32),
 nonce BYTEA NOT NULL CHECK(octet_length(nonce)=32),
 expires_at TIMESTAMPTZ NOT NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 consumed_at TIMESTAMPTZ
);
CREATE TABLE uem_agent_software_tasks (
 id UUID PRIMARY KEY,
 tenant_id BIGINT NOT NULL,
 site_id BIGINT NOT NULL,
 device_id UUID NOT NULL,
 preparation_id UUID NOT NULL,
 revision_id UUID NOT NULL,
 recipient_id UUID NOT NULL,
 certificate_hash TEXT NOT NULL CHECK(certificate_hash ~ '^[a-f0-9]{64}$'),
 certificate BYTEA NOT NULL CHECK(octet_length(certificate) BETWEEN 1 AND 16384),
 authority BYTEA NOT NULL CHECK(octet_length(authority) BETWEEN 1 AND 16384),
 nonce_hash TEXT NOT NULL CHECK(nonce_hash ~ '^[a-f0-9]{64}$'),
 task_hash TEXT NOT NULL CHECK(task_hash ~ '^[a-f0-9]{64}$'),
 task_context BYTEA NOT NULL CHECK(octet_length(task_context) BETWEEN 1 AND 8192),
 envelope BYTEA NOT NULL CHECK(octet_length(envelope) BETWEEN 1 AND 65536),
 actor TEXT NOT NULL CHECK(length(actor)>0),
 status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','delivered','reported','uncertain','restart_required','cancelled','expired')),
 created_at TIMESTAMPTZ NOT NULL,
 expires_at TIMESTAMPTZ NOT NULL,
 delivered_at TIMESTAMPTZ,
 result BYTEA CHECK(octet_length(result)<=65536),
 result_certificate BYTEA CHECK(octet_length(result_certificate) BETWEEN 1 AND 16384),
 result_hash TEXT CHECK(result_hash ~ '^[a-f0-9]{64}$'),
 completed_at TIMESTAMPTZ,
 UNIQUE(tenant_id,site_id,device_id,id),
 UNIQUE(tenant_id,preparation_id),
 FOREIGN KEY(tenant_id,site_id,device_id) REFERENCES uem_agent_identities(tenant_id,site_id,id) ON DELETE RESTRICT,
 CHECK(expires_at>created_at AND expires_at<=created_at+interval '24 hours'),
 CHECK((result IS NULL)=(result_certificate IS NULL) AND (result IS NULL)=(result_hash IS NULL)),
 CHECK(status NOT IN ('reported','restart_required') OR result IS NOT NULL),
 CHECK(status NOT IN ('delivered','reported','restart_required') OR delivered_at IS NOT NULL)
);
CREATE UNIQUE INDEX uem_agent_software_active ON uem_agent_software_tasks(device_id)
 WHERE status IN ('pending','delivered','uncertain','restart_required');
CREATE INDEX uem_agent_software_expiry ON uem_agent_software_tasks(expires_at)
 WHERE status IN ('pending','delivered');
CREATE FUNCTION uem_agent_software_task_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP IN ('DELETE','TRUNCATE') THEN RAISE EXCEPTION 'Windows software task history cannot be deleted'; END IF;
 IF (to_jsonb(NEW)-'status'-'delivered_at'-'result'-'result_certificate'-'result_hash'-'completed_at'-'envelope')
    IS DISTINCT FROM (to_jsonb(OLD)-'status'-'delivered_at'-'result'-'result_certificate'-'result_hash'-'completed_at'-'envelope')
    OR OLD.status IN ('reported','cancelled','expired','restart_required')
    OR OLD.result IS NOT NULL
    OR (OLD.delivered_at IS NOT NULL AND NEW.delivered_at IS DISTINCT FROM OLD.delivered_at)
    OR NEW.envelope IS DISTINCT FROM OLD.envelope
    OR (OLD.status='pending' AND NEW.status NOT IN ('delivered','cancelled','expired'))
    OR (OLD.status='delivered' AND NEW.status NOT IN ('reported','uncertain','restart_required'))
    OR (OLD.status='uncertain' AND NEW.status NOT IN ('reported','uncertain','restart_required')) THEN
  RAISE EXCEPTION 'Windows software task intent and evidence are immutable';
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER uem_agent_software_task_guard BEFORE UPDATE OR DELETE ON uem_agent_software_tasks FOR EACH ROW EXECUTE FUNCTION uem_agent_software_task_guard();
CREATE TRIGGER uem_agent_software_task_truncate BEFORE TRUNCATE ON uem_agent_software_tasks FOR EACH STATEMENT EXECUTE FUNCTION uem_agent_software_task_guard();
CREATE FUNCTION uem_agent_software_identity_change() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.revoked_at IS NOT NULL OR NEW.certificate_expires_at<=clock_timestamp()
 OR NEW.certificate_hash IS DISTINCT FROM OLD.certificate_hash
 OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id OR NEW.site_id IS DISTINCT FROM OLD.site_id THEN
  UPDATE uem_agent_software_tasks SET status='cancelled',completed_at=clock_timestamp() WHERE device_id=NEW.id AND status='pending';
  UPDATE uem_agent_software_tasks SET status='uncertain' WHERE device_id=NEW.id AND status='delivered';
  DELETE FROM uem_agent_software_challenges WHERE device_id=NEW.id;
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER uem_agent_software_identity_change AFTER UPDATE OF revoked_at,certificate_expires_at,certificate_hash,tenant_id,site_id ON uem_agent_identities
 FOR EACH ROW EXECUTE FUNCTION uem_agent_software_identity_change();
