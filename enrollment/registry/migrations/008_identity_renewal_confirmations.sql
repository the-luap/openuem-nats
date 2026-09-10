-- A confirmation is permanent evidence for exactly one prepared generation.
-- The authenticated payload is checked against issuance before retries succeed.
CREATE TABLE uem_agent_identity_renewal_confirmations (
    id UUID PRIMARY KEY REFERENCES uem_agent_identity_renewals(id) ON DELETE RESTRICT,
    device_id UUID NOT NULL REFERENCES uem_agent_identities(id) ON DELETE RESTRICT,
    certificate_hash TEXT NOT NULL CHECK (certificate_hash ~ '^[0-9a-f]{64}$'),
    encrypted_record BYTEA NOT NULL CHECK (octet_length(encrypted_record) BETWEEN 29 AND 16384),
    confirmed_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX uem_agent_identity_renewal_confirmations_device ON uem_agent_identity_renewal_confirmations(device_id);
CREATE TRIGGER uem_agent_identity_renewal_confirmation_immutable
    BEFORE UPDATE OR DELETE ON uem_agent_identity_renewal_confirmations
    FOR EACH ROW EXECUTE FUNCTION uem_agent_renewal_immutable();
CREATE TRIGGER uem_agent_identity_renewal_confirmation_truncate
    BEFORE TRUNCATE ON uem_agent_identity_renewal_confirmations
    FOR EACH STATEMENT EXECUTE FUNCTION uem_agent_renewal_immutable();
