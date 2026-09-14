-- Extend platform admission without changing any existing invitation, identity,
-- key reservation, renewal history or platform-specific command authority.
ALTER TABLE uem_agent_invitations
    DROP CONSTRAINT uem_agent_invitations_platform_check,
    ADD CONSTRAINT uem_agent_invitations_platform_check
        CHECK (platform IN ('windows', 'macos', 'linux'));

ALTER TABLE uem_agent_identities
    DROP CONSTRAINT uem_agent_identities_platform_check,
    ADD CONSTRAINT uem_agent_identities_platform_check
        CHECK (platform IN ('windows', 'macos', 'linux'));
