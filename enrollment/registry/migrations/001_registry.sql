CREATE TABLE uem_agent_authorities (
    tenant_id BIGINT PRIMARY KEY REFERENCES tenants(id) ON DELETE RESTRICT,
    organization TEXT NOT NULL,
    public_origin TEXT NOT NULL,
    certificate BYTEA NOT NULL,
    encrypted_key BYTEA NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE uem_agent_invitations (
    id UUID PRIMARY KEY,
    tenant_id BIGINT NOT NULL REFERENCES uem_agent_authorities(tenant_id) ON DELETE RESTRICT,
    site_id BIGINT NOT NULL REFERENCES sites(id) ON DELETE RESTRICT,
    token_hash TEXT NOT NULL UNIQUE,
    platform TEXT NOT NULL CHECK (platform IN ('windows','macos')),
    architecture TEXT NOT NULL CHECK (architecture IN ('amd64','arm64')),
    max_uses INTEGER NOT NULL CHECK (max_uses BETWEEN 1 AND 1000),
    uses INTEGER NOT NULL DEFAULT 0 CHECK (uses >= 0 AND uses <= max_uses),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE uem_agent_identities (
    id UUID PRIMARY KEY,
    tenant_id BIGINT NOT NULL REFERENCES uem_agent_authorities(tenant_id) ON DELETE RESTRICT,
    site_id BIGINT NOT NULL REFERENCES sites(id) ON DELETE RESTRICT,
    invitation_id UUID NOT NULL REFERENCES uem_agent_invitations(id) ON DELETE RESTRICT,
    key_binding TEXT NOT NULL UNIQUE,
    certificate_key_hash TEXT NOT NULL UNIQUE,
    broker_key TEXT NOT NULL UNIQUE,
    platform TEXT NOT NULL CHECK (platform IN ('windows','macos')),
    architecture TEXT NOT NULL CHECK (architecture IN ('amd64','arm64')),
    display_name TEXT NOT NULL,
    public_origin TEXT NOT NULL,
    certificate BYTEA NOT NULL,
    authority_certificate BYTEA NOT NULL,
    certificate_hash TEXT NOT NULL UNIQUE,
    certificate_expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    enrolled_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at TIMESTAMPTZ
);
CREATE INDEX uem_agent_identities_scope ON uem_agent_identities(tenant_id,site_id);

-- Sessions are recorded in the same transaction that verifies active identity.
-- Revocation marks them for repeated disconnect attempts until their lease ends.
CREATE TABLE uem_agent_broker_sessions (
    server_id TEXT NOT NULL,
    client_id BIGINT NOT NULL CHECK (client_id > 0),
    device_id UUID NOT NULL REFERENCES uem_agent_identities(id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL,
    disconnect_at TIMESTAMPTZ,
    attempted_at TIMESTAMPTZ,
    PRIMARY KEY(server_id,client_id)
);
CREATE INDEX uem_agent_broker_sessions_device ON uem_agent_broker_sessions(device_id);

CREATE TABLE uem_agent_audit (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id BIGINT NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    site_id BIGINT REFERENCES sites(id) ON DELETE RESTRICT,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    resource_id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX uem_agent_audit_scope_time ON uem_agent_audit(tenant_id,site_id,created_at DESC);
