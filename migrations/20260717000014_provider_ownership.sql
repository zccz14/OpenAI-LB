-- Existing configured installations already have one root user. A legacy
-- pre-setup database can have providers before root is bound, so owner_id is
-- temporarily nullable for that upgrade path; setup backfills it when the
-- unique root is created. Every provider created by current code has an owner.
ALTER TABLE providers
ADD COLUMN owner_id TEXT REFERENCES users(id) ON DELETE CASCADE;

UPDATE providers
SET owner_id = (SELECT id FROM users WHERE role = 'root')
WHERE owner_id IS NULL;

CREATE INDEX providers_owner_idx ON providers(owner_id, created_at DESC);

CREATE TABLE provider_grants (
    provider_id TEXT NOT NULL REFERENCES providers(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    PRIMARY KEY(provider_id, user_id)
) WITHOUT ROWID;

CREATE INDEX provider_grants_user_idx ON provider_grants(user_id, provider_id);
