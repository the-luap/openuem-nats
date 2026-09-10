-- The routing worker's completed receipt is not confirmation that the console
-- retained the returned recovery key. Only the trusted key-processing service
-- writes this authenticated acknowledgement in its own reconciliation commit.
CREATE TABLE uem_agent_rotation_reconciliations (
    task_id UUID PRIMARY KEY REFERENCES uem_agent_rotation_tasks(id) ON DELETE RESTRICT,
    device_id UUID NOT NULL REFERENCES uem_agent_identities(id) ON DELETE RESTRICT,
    encrypted_record BYTEA NOT NULL CHECK (octet_length(encrypted_record) BETWEEN 29 AND 16384)
);
CREATE INDEX uem_agent_rotation_reconciliations_device ON uem_agent_rotation_reconciliations(device_id);
CREATE TRIGGER uem_agent_rotation_reconciliation_immutable
    BEFORE UPDATE OR DELETE ON uem_agent_rotation_reconciliations
    FOR EACH ROW EXECUTE FUNCTION uem_agent_renewal_immutable();
CREATE TRIGGER uem_agent_rotation_reconciliation_truncate
    BEFORE TRUNCATE ON uem_agent_rotation_reconciliations
    FOR EACH STATEMENT EXECUTE FUNCTION uem_agent_renewal_immutable();
