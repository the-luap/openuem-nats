-- Hardware evidence is accepted only by the individually authorized worker path.
ALTER TABLE uem_agent_identities ADD CONSTRAINT uem_agent_identity_hardware_scope UNIQUE(tenant_id,site_id,id);
CREATE TABLE uem_agent_hardware (
 device_id UUID PRIMARY KEY,
 tenant_id BIGINT NOT NULL,
 site_id BIGINT NOT NULL,
 model TEXT NOT NULL,
 serial TEXT NOT NULL,
 platform_uuid TEXT NOT NULL,
 provisioning_udid TEXT NOT NULL DEFAULT '',
 binding_challenge_id UUID,
 binding_device_id UUID,
 binding_token_hash TEXT,
 observed_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY(tenant_id,site_id,device_id) REFERENCES uem_agent_identities(tenant_id,site_id,id) ON DELETE CASCADE,
 CHECK ((binding_challenge_id IS NULL AND binding_device_id IS NULL AND binding_token_hash IS NULL)
   OR (binding_challenge_id IS NOT NULL AND binding_device_id IS NOT NULL AND binding_token_hash IS NOT NULL AND binding_token_hash ~ '^[a-f0-9]{64}$'))
);
CREATE INDEX uem_agent_hardware_scope ON uem_agent_hardware(tenant_id,site_id,observed_at,device_id);
CREATE INDEX uem_agent_hardware_binding ON uem_agent_hardware(binding_challenge_id) WHERE binding_challenge_id IS NOT NULL;
