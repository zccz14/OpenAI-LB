ALTER TABLE api_calls
ADD COLUMN thread_id TEXT;

CREATE INDEX api_calls_thread_time_idx
ON api_calls(thread_id, created_at DESC);
