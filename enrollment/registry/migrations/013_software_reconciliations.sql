-- Separate immutable read-only observations preserve the original executable
-- envelope and execution receipt. A release must reference an accepted definite
-- reconciliation in the same original organization/site/device/task scope.
CREATE TABLE uem_agent_software_reconciliations (
 id UUID PRIMARY KEY,
 tenant_id BIGINT NOT NULL,
 site_id BIGINT NOT NULL,
 device_id UUID NOT NULL,
 original_task_id UUID NOT NULL,
 certificate_hash TEXT NOT NULL CHECK(certificate_hash ~ '^[a-f0-9]{64}$'),
 certificate BYTEA NOT NULL CHECK(octet_length(certificate) BETWEEN 1 AND 16384),
 task_hash TEXT NOT NULL CHECK(task_hash ~ '^[a-f0-9]{64}$'),
 task_context BYTEA NOT NULL CHECK(octet_length(task_context) BETWEEN 1 AND 16384),
 envelope BYTEA NOT NULL CHECK(octet_length(envelope) BETWEEN 1 AND 65536),
 actor TEXT NOT NULL CHECK(length(actor)>0),
 status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','delivered','reported','cancelled','expired')),
 created_at TIMESTAMPTZ NOT NULL,
 expires_at TIMESTAMPTZ NOT NULL,
 delivered_at TIMESTAMPTZ,
 result BYTEA CHECK(octet_length(result) BETWEEN 1 AND 65536),
 result_hash TEXT CHECK(result_hash ~ '^[a-f0-9]{64}$'),
 outcome TEXT CHECK(outcome IN ('observed','drifted','unknown','waiting_for_boot','unavailable')),
 completed_at TIMESTAMPTZ,
 UNIQUE(tenant_id,site_id,device_id,original_task_id,id),
 FOREIGN KEY(tenant_id,site_id,device_id,original_task_id)
  REFERENCES uem_agent_software_tasks(tenant_id,site_id,device_id,id) ON DELETE RESTRICT,
 CHECK(expires_at>created_at AND expires_at<=created_at+interval '1 hour'),
 CHECK((result IS NULL)=(result_hash IS NULL) AND (result IS NULL)=(outcome IS NULL)),
 CHECK((status='reported')=(result IS NOT NULL)),
 CHECK(status NOT IN ('delivered','reported') OR delivered_at IS NOT NULL),
 CHECK((status IN ('reported','cancelled','expired'))=(completed_at IS NOT NULL))
);
CREATE UNIQUE INDEX uem_agent_software_reconciliation_active ON uem_agent_software_reconciliations(original_task_id)
 WHERE status IN ('pending','delivered');
CREATE INDEX uem_agent_software_reconciliation_delivery ON uem_agent_software_reconciliations(device_id,created_at,id)
 WHERE status IN ('pending','delivered');

CREATE FUNCTION uem_agent_software_reconciliation_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP IN ('DELETE','TRUNCATE') THEN RAISE EXCEPTION 'Windows software reconciliation history cannot be deleted'; END IF;
 IF (to_jsonb(NEW)-'status'-'delivered_at'-'result'-'result_hash'-'outcome'-'completed_at')
    IS DISTINCT FROM (to_jsonb(OLD)-'status'-'delivered_at'-'result'-'result_hash'-'outcome'-'completed_at')
    OR OLD.status IN ('reported','cancelled') OR OLD.result IS NOT NULL
    OR (OLD.delivered_at IS NOT NULL AND NEW.delivered_at IS DISTINCT FROM OLD.delivered_at)
    OR (OLD.status='pending' AND NEW.status NOT IN ('delivered','cancelled','expired'))
    OR (OLD.status='delivered' AND NEW.status NOT IN ('reported','expired'))
    OR (OLD.status='expired' AND (OLD.delivered_at IS NULL OR NEW.status<>'reported')) THEN
  RAISE EXCEPTION 'Windows software reconciliation intent and evidence are immutable';
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER uem_agent_software_reconciliation_guard BEFORE UPDATE OR DELETE ON uem_agent_software_reconciliations
 FOR EACH ROW EXECUTE FUNCTION uem_agent_software_reconciliation_guard();
CREATE TRIGGER uem_agent_software_reconciliation_truncate BEFORE TRUNCATE ON uem_agent_software_reconciliations
 FOR EACH STATEMENT EXECUTE FUNCTION uem_agent_software_reconciliation_guard();

ALTER TABLE uem_agent_software_tasks ADD COLUMN reconciliation_id UUID;
ALTER TABLE uem_agent_software_tasks ADD COLUMN reconciled_at TIMESTAMPTZ;
ALTER TABLE uem_agent_software_tasks ADD CONSTRAINT uem_agent_software_release_pair
 CHECK((reconciliation_id IS NULL)=(reconciled_at IS NULL));
ALTER TABLE uem_agent_software_tasks ADD CONSTRAINT uem_agent_software_release_scope
 FOREIGN KEY(tenant_id,site_id,device_id,id,reconciliation_id)
 REFERENCES uem_agent_software_reconciliations(tenant_id,site_id,device_id,original_task_id,id) ON DELETE RESTRICT;
DROP INDEX uem_agent_software_active;
CREATE UNIQUE INDEX uem_agent_software_active ON uem_agent_software_tasks(device_id)
 WHERE status IN ('pending','delivered','uncertain','restart_required') AND reconciliation_id IS NULL;

CREATE OR REPLACE FUNCTION uem_agent_software_task_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP IN ('DELETE','TRUNCATE') THEN RAISE EXCEPTION 'Windows software task history cannot be deleted'; END IF;
 IF NEW.reconciliation_id IS DISTINCT FROM OLD.reconciliation_id OR NEW.reconciled_at IS DISTINCT FROM OLD.reconciled_at THEN
  IF OLD.reconciliation_id IS NOT NULL OR NEW.reconciliation_id IS NULL OR NEW.reconciled_at IS NULL
     OR OLD.status NOT IN ('uncertain','restart_required') OR OLD.delivered_at IS NULL
     OR (to_jsonb(NEW)-'reconciliation_id'-'reconciled_at') IS DISTINCT FROM (to_jsonb(OLD)-'reconciliation_id'-'reconciled_at')
     OR NOT EXISTS(SELECT 1 FROM uem_agent_software_reconciliations r
       WHERE r.id=NEW.reconciliation_id AND r.original_task_id=OLD.id AND r.device_id=OLD.device_id
       AND r.tenant_id=OLD.tenant_id AND r.site_id=OLD.site_id AND r.status='reported'
       AND r.result IS NOT NULL AND r.outcome IN ('observed','drifted') AND r.delivered_at IS NOT NULL
       AND r.completed_at=NEW.reconciled_at) THEN
   RAISE EXCEPTION 'Windows software reservation release requires retained reconciliation evidence';
  END IF;
  RETURN NEW;
 END IF;
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

CREATE FUNCTION uem_agent_software_reconciliation_identity_change() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.revoked_at IS NOT NULL OR NEW.certificate_expires_at<=clock_timestamp()
 OR NEW.certificate_hash IS DISTINCT FROM OLD.certificate_hash
 OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id OR NEW.site_id IS DISTINCT FROM OLD.site_id THEN
  UPDATE uem_agent_software_reconciliations SET status='cancelled',completed_at=clock_timestamp()
   WHERE device_id=NEW.id AND status='pending';
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER uem_agent_software_reconciliation_identity_change AFTER UPDATE OF revoked_at,certificate_expires_at,certificate_hash,tenant_id,site_id ON uem_agent_identities
 FOR EACH ROW EXECUTE FUNCTION uem_agent_software_reconciliation_identity_change();
