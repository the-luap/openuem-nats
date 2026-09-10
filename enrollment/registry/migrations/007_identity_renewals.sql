-- Keys remain owned by one device across pending, confirmed and retired
-- generations. This also protects initial enrollment by older registry clients.
CREATE TABLE uem_agent_key_reservations (
    kind TEXT NOT NULL CHECK (kind IN ('certificate','broker')),
    key_value TEXT NOT NULL CHECK (length(key_value) BETWEEN 1 AND 512),
    device_id UUID NOT NULL REFERENCES uem_agent_identities(id) ON DELETE RESTRICT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY(kind,key_value)
);
CREATE INDEX uem_agent_key_reservations_device ON uem_agent_key_reservations(device_id);

INSERT INTO uem_agent_key_reservations(kind,key_value,device_id)
SELECT 'certificate',certificate_key_hash,id FROM uem_agent_identities
UNION ALL SELECT 'broker',broker_key,id FROM uem_agent_identities;

CREATE FUNCTION uem_agent_identity_key_reservations() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE key_kind TEXT; key_value TEXT; owner_id UUID;
BEGIN
    FOR key_kind,key_value IN SELECT 'certificate',NEW.certificate_key_hash UNION ALL SELECT 'broker',NEW.broker_key LOOP
        EXECUTE format('INSERT INTO %I.uem_agent_key_reservations(kind,key_value,device_id) VALUES($1,$2,$3) ON CONFLICT(kind,key_value) DO NOTHING',TG_TABLE_SCHEMA)
            USING key_kind,key_value,NEW.id;
        EXECUTE format('SELECT device_id FROM %I.uem_agent_key_reservations WHERE kind=$1 AND key_value=$2',TG_TABLE_SCHEMA)
            INTO owner_id USING key_kind,key_value;
        IF owner_id IS DISTINCT FROM NEW.id THEN
            RAISE EXCEPTION 'agent identity key is already reserved' USING ERRCODE='23505';
        END IF;
    END LOOP;
    RETURN NEW;
END
$$;
CREATE TRIGGER uem_agent_identity_key_reservations
    AFTER INSERT OR UPDATE OF certificate_key_hash,broker_key ON uem_agent_identities
    FOR EACH ROW EXECUTE FUNCTION uem_agent_identity_key_reservations();

CREATE TABLE uem_agent_identity_renewals (
    id UUID PRIMARY KEY,
    device_id UUID NOT NULL REFERENCES uem_agent_identities(id) ON DELETE RESTRICT,
    tenant_id BIGINT NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    site_id BIGINT NOT NULL REFERENCES sites(id) ON DELETE RESTRICT,
    source_certificate_hash TEXT NOT NULL CHECK (source_certificate_hash ~ '^[0-9a-f]{64}$'),
    certificate_hash TEXT NOT NULL UNIQUE CHECK (certificate_hash ~ '^[0-9a-f]{64}$'),
    intent_digest TEXT NOT NULL CHECK (intent_digest ~ '^[0-9a-f]{64}$'),
    encrypted_record BYTEA NOT NULL CHECK (octet_length(encrypted_record) BETWEEN 29 AND 262144),
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL CHECK (expires_at>created_at),
    CHECK (expires_at<=created_at+INTERVAL '168 hours')
);
CREATE INDEX uem_agent_identity_renewals_device ON uem_agent_identity_renewals(device_id,created_at,id);

CREATE FUNCTION uem_agent_renewal_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'agent identity renewal evidence is immutable' USING ERRCODE='55000';
END
$$;
CREATE TRIGGER uem_agent_key_reservation_immutable BEFORE UPDATE OR DELETE ON uem_agent_key_reservations
    FOR EACH ROW EXECUTE FUNCTION uem_agent_renewal_immutable();
CREATE TRIGGER uem_agent_key_reservation_truncate BEFORE TRUNCATE ON uem_agent_key_reservations
    FOR EACH STATEMENT EXECUTE FUNCTION uem_agent_renewal_immutable();
CREATE TRIGGER uem_agent_identity_renewal_immutable BEFORE UPDATE OR DELETE ON uem_agent_identity_renewals
    FOR EACH ROW EXECUTE FUNCTION uem_agent_renewal_immutable();
CREATE TRIGGER uem_agent_identity_renewal_truncate BEFORE TRUNCATE ON uem_agent_identity_renewals
    FOR EACH STATEMENT EXECUTE FUNCTION uem_agent_renewal_immutable();
