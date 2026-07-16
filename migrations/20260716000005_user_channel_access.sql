-- New tenant users must be explicitly granted access before their API keys can
-- reach any CodeX channel. Administrators remain authorized by role.
ALTER TABLE users ADD COLUMN channel_access INTEGER NOT NULL DEFAULT 0 CHECK(channel_access IN (0,1));
