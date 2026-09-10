-- A fresh encrypted console admission binds a read-only validation challenge
-- to one exact historical rotation receipt and the retained current key. An
-- unrelated earlier validation or a mutable success flag cannot replace it.
CREATE TABLE uem_agent_rotation_recovery_checks (
    id UUID PRIMARY KEY REFERENCES uem_agent_recovery_tasks(id) ON DELETE RESTRICT,
    device_id UUID NOT NULL REFERENCES uem_agent_identities(id) ON DELETE RESTRICT,
    rotation_task_id UUID NOT NULL REFERENCES uem_agent_rotation_tasks(id) ON DELETE RESTRICT,
    encrypted_record BYTEA NOT NULL CHECK (octet_length(encrypted_record) BETWEEN 29 AND 32768),
    created_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX uem_agent_rotation_recovery_checks_device ON uem_agent_rotation_recovery_checks(device_id,created_at,id);
CREATE INDEX uem_agent_rotation_recovery_checks_rotation ON uem_agent_rotation_recovery_checks(rotation_task_id,created_at,id);
CREATE TRIGGER uem_agent_rotation_recovery_check_immutable
    BEFORE UPDATE OR DELETE ON uem_agent_rotation_recovery_checks
    FOR EACH ROW EXECUTE FUNCTION uem_agent_renewal_immutable();
CREATE TRIGGER uem_agent_rotation_recovery_check_truncate
    BEFORE TRUNCATE ON uem_agent_rotation_recovery_checks
    FOR EACH STATEMENT EXECUTE FUNCTION uem_agent_renewal_immutable();
ALTER TABLE uem_agent_rotation_reconciliations ADD COLUMN recovery_check_id UUID
    REFERENCES uem_agent_rotation_recovery_checks(id) ON DELETE RESTRICT;
