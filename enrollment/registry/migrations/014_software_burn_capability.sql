-- Zero preserves the exact legacy wire contract. Only a new signed registration
-- can replace it with a supported Burn capability; a challenge is not authority.
ALTER TABLE uem_agent_software_recipients ADD COLUMN burn_version INTEGER NOT NULL DEFAULT 0 CHECK(burn_version IN (0,1));
ALTER TABLE uem_agent_software_challenges ADD COLUMN burn_version INTEGER NOT NULL DEFAULT 0 CHECK(burn_version IN (0,1));
