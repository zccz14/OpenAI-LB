ALTER TABLE api_calls ADD COLUMN affinity_hash TEXT;
ALTER TABLE api_calls ADD COLUMN affinity_source TEXT;
CREATE INDEX api_calls_affinity_time_idx ON api_calls(affinity_hash,created_at DESC);
