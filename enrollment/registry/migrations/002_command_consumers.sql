CREATE TABLE uem_agent_command_consumers (
    device_id UUID PRIMARY KEY REFERENCES uem_agent_identities(id) ON DELETE CASCADE,
    desired_active BOOLEAN NOT NULL,
    revision BIGINT NOT NULL DEFAULT 1 CHECK (revision > 0),
    completed_revision BIGINT NOT NULL DEFAULT 0 CHECK (completed_revision >= 0),
    attempted_at TIMESTAMPTZ,
    lease_token UUID,
    reconcile_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX uem_agent_command_consumers_due ON uem_agent_command_consumers(reconcile_at,attempted_at);
CREATE INDEX uem_agent_identities_certificate_expiry ON uem_agent_identities(certificate_expires_at) WHERE revoked_at IS NULL;

-- Keep issuance and revocation atomic with command-consumer work, including
-- trusted components still using a previous additive registry library version.
CREATE FUNCTION uem_agent_queue_command_consumer() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE wanted BOOLEAN;
BEGIN
    wanted := NEW.revoked_at IS NULL AND NEW.certificate_expires_at > clock_timestamp()
        AND EXISTS(SELECT 1 FROM sites WHERE id=NEW.site_id AND tenant_sites=NEW.tenant_id);
    INSERT INTO uem_agent_command_consumers(device_id,desired_active) VALUES(NEW.id,wanted)
    ON CONFLICT(device_id) DO UPDATE SET
        desired_active=EXCLUDED.desired_active,
        revision=uem_agent_command_consumers.revision+1,
        attempted_at=NULL, lease_token=NULL, reconcile_at=clock_timestamp()
    WHERE uem_agent_command_consumers.desired_active IS DISTINCT FROM EXCLUDED.desired_active;
    RETURN NEW;
END
$$;
CREATE TRIGGER uem_agent_identity_command_consumer
    AFTER INSERT OR UPDATE OF revoked_at,certificate_expires_at,tenant_id,site_id ON uem_agent_identities
    FOR EACH ROW EXECUTE FUNCTION uem_agent_queue_command_consumer();

CREATE FUNCTION uem_agent_site_command_consumers() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    UPDATE uem_agent_command_consumers q SET
        desired_active=(i.revoked_at IS NULL AND i.certificate_expires_at>clock_timestamp() AND COALESCE(i.tenant_id=NEW.tenant_sites,false)),
        revision=q.revision+1, attempted_at=NULL, lease_token=NULL, reconcile_at=clock_timestamp()
    FROM uem_agent_identities i
    WHERE q.device_id=i.id AND i.site_id=NEW.id
      AND q.desired_active IS DISTINCT FROM
        (i.revoked_at IS NULL AND i.certificate_expires_at>clock_timestamp() AND COALESCE(i.tenant_id=NEW.tenant_sites,false));
    RETURN NEW;
END
$$;
CREATE TRIGGER uem_agent_site_command_consumers
    AFTER UPDATE OF tenant_sites ON sites
    FOR EACH ROW EXECUTE FUNCTION uem_agent_site_command_consumers();

INSERT INTO uem_agent_command_consumers(device_id,desired_active)
SELECT i.id, i.revoked_at IS NULL AND i.certificate_expires_at>clock_timestamp()
    AND EXISTS(SELECT 1 FROM sites WHERE id=i.site_id AND tenant_sites=i.tenant_id)
FROM uem_agent_identities i;
