-- Permanent cancellation is the only authority to recover the original keys
-- after an uncertain confirmation. Enforce the exclusion in PostgreSQL too:
-- an older server must not activate a candidate after cancellation committed.
CREATE TABLE uem_agent_identity_renewal_cancellations (
    id UUID PRIMARY KEY REFERENCES uem_agent_identity_renewals(id) ON DELETE RESTRICT,
    device_id UUID NOT NULL REFERENCES uem_agent_identities(id) ON DELETE RESTRICT,
    source_certificate_hash TEXT NOT NULL CHECK (source_certificate_hash ~ '^[0-9a-f]{64}$'),
    certificate_hash TEXT NOT NULL UNIQUE CHECK (certificate_hash ~ '^[0-9a-f]{64}$'),
    encrypted_record BYTEA NOT NULL CHECK (octet_length(encrypted_record) BETWEEN 29 AND 16384),
    cancelled_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX uem_agent_identity_renewal_cancellations_device ON uem_agent_identity_renewal_cancellations(device_id);
CREATE TRIGGER uem_agent_identity_renewal_cancellation_immutable
    BEFORE UPDATE OR DELETE ON uem_agent_identity_renewal_cancellations
    FOR EACH ROW EXECUTE FUNCTION uem_agent_renewal_immutable();
CREATE TRIGGER uem_agent_identity_renewal_cancellation_truncate
    BEFORE TRUNCATE ON uem_agent_identity_renewal_cancellations
    FOR EACH STATEMENT EXECUTE FUNCTION uem_agent_renewal_immutable();

CREATE FUNCTION uem_agent_identity_renewal_cancellation_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    current_hash TEXT;
    current_expiry TIMESTAMPTZ;
    revoked TIMESTAMPTZ;
    valid_issuance BOOLEAN;
    confirmed BOOLEAN;
BEGIN
    -- Match the application lock order. A concurrent confirmation either commits
    -- first, or observes this permanent cancellation before changing identity.
    EXECUTE format('SELECT certificate_hash,certificate_expires_at,revoked_at FROM %I.uem_agent_identities WHERE id=$1 FOR UPDATE',TG_TABLE_SCHEMA)
        INTO current_hash,current_expiry,revoked USING NEW.device_id;
    EXECUTE format('SELECT EXISTS(SELECT 1 FROM %I.uem_agent_identity_renewals WHERE id=$1 AND device_id=$2 AND source_certificate_hash=$3 AND certificate_hash=$4 AND created_at<=$5)',TG_TABLE_SCHEMA)
        INTO valid_issuance USING NEW.id,NEW.device_id,NEW.source_certificate_hash,NEW.certificate_hash,NEW.cancelled_at;
    EXECUTE format('SELECT EXISTS(SELECT 1 FROM %I.uem_agent_identity_renewal_confirmations WHERE id=$1 OR certificate_hash=$2)',TG_TABLE_SCHEMA)
        INTO confirmed USING NEW.id,NEW.certificate_hash;
    IF NOT valid_issuance OR confirmed OR revoked IS NOT NULL OR current_hash IS DISTINCT FROM NEW.source_certificate_hash OR current_expiry IS NULL OR current_expiry<=clock_timestamp() OR NEW.cancelled_at>=current_expiry THEN
        RAISE EXCEPTION 'agent identity renewal cannot be cancelled' USING ERRCODE='55000';
    END IF;
    -- Publish a new MVCC row version without changing any identity value or
    -- firing certificate/scope/recovery/consumer triggers. Older transactions
    -- using REPEATABLE READ or SERIALIZABLE must fail their stale identity write
    -- instead of checking cancellation against a pre-cancellation snapshot.
    EXECUTE format('UPDATE %I.uem_agent_identities SET key_binding=key_binding WHERE id=$1',TG_TABLE_SCHEMA)
        USING NEW.device_id;
    RETURN NEW;
END
$$;
CREATE TRIGGER uem_agent_identity_renewal_cancellation_guard
    BEFORE INSERT ON uem_agent_identity_renewal_cancellations
    FOR EACH ROW EXECUTE FUNCTION uem_agent_identity_renewal_cancellation_guard();

CREATE FUNCTION uem_agent_identity_renewal_activation_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE cancelled BOOLEAN;
BEGIN
    EXECUTE format('SELECT EXISTS(SELECT 1 FROM %I.uem_agent_identity_renewal_cancellations WHERE certificate_hash=$1)',TG_TABLE_SCHEMA)
        INTO cancelled USING NEW.certificate_hash;
    IF cancelled THEN
        RAISE EXCEPTION 'agent identity renewal is permanently cancelled' USING ERRCODE='55000';
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER uem_agent_identity_renewal_activation_guard
    BEFORE INSERT OR UPDATE OF certificate_hash ON uem_agent_identities
    FOR EACH ROW EXECUTE FUNCTION uem_agent_identity_renewal_activation_guard();

CREATE FUNCTION uem_agent_identity_renewal_confirmation_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    current_hash TEXT;
    valid_issuance BOOLEAN;
    cancelled BOOLEAN;
BEGIN
    EXECUTE format('SELECT certificate_hash FROM %I.uem_agent_identities WHERE id=$1 FOR UPDATE',TG_TABLE_SCHEMA)
        INTO current_hash USING NEW.device_id;
    EXECUTE format('SELECT EXISTS(SELECT 1 FROM %I.uem_agent_identity_renewals WHERE id=$1 AND device_id=$2 AND certificate_hash=$3 AND created_at<=$4 AND expires_at>$4)',TG_TABLE_SCHEMA)
        INTO valid_issuance USING NEW.id,NEW.device_id,NEW.certificate_hash,NEW.confirmed_at;
    EXECUTE format('SELECT EXISTS(SELECT 1 FROM %I.uem_agent_identity_renewal_cancellations WHERE id=$1 OR certificate_hash=$2)',TG_TABLE_SCHEMA)
        INTO cancelled USING NEW.id,NEW.certificate_hash;
    IF cancelled OR NOT valid_issuance OR current_hash IS DISTINCT FROM NEW.certificate_hash THEN
        RAISE EXCEPTION 'agent identity renewal cannot be confirmed' USING ERRCODE='55000';
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER uem_agent_identity_renewal_confirmation_guard
    BEFORE INSERT ON uem_agent_identity_renewal_confirmations
    FOR EACH ROW EXECUTE FUNCTION uem_agent_identity_renewal_confirmation_guard();
