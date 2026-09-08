-- A read-only proof may resolve a stopped, uncertain mutation. Keeping the
-- selected proof on the original attempt prevents reuse of an earlier check.
ALTER TABLE uem_agent_rotation_tasks
 ADD COLUMN resolution_task_id UUID REFERENCES uem_agent_recovery_tasks(id),
 ADD COLUMN resolved_at TIMESTAMPTZ,
 ADD CONSTRAINT uem_agent_rotation_resolution_time CHECK(resolved_at IS NULL OR (resolution_task_id IS NOT NULL AND status='completed'));
