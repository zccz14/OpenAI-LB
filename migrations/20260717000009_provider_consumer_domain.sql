-- The product domain now names the two sides of the proxy explicitly:
-- upstream providers supply capacity, downstream consumers use the proxy.
ALTER TABLE channels RENAME TO providers;
ALTER TABLE api_keys RENAME TO consumers;
ALTER TABLE users RENAME COLUMN channel_access TO provider_access;
ALTER TABLE affinities RENAME COLUMN channel_id TO provider_id;
ALTER TABLE api_calls RENAME COLUMN api_key_id TO consumer_id;
ALTER TABLE api_calls RENAME COLUMN channel_id TO provider_id;

DROP INDEX IF EXISTS api_keys_user_idx;
DROP INDEX IF EXISTS channels_available_idx;
DROP INDEX IF EXISTS api_calls_key_time_idx;
CREATE INDEX consumers_user_idx ON consumers(user_id, created_at DESC);
CREATE INDEX providers_available_idx ON providers(manual_disabled, status, cooldown_until);
CREATE INDEX api_calls_consumer_time_idx ON api_calls(consumer_id, created_at DESC);
