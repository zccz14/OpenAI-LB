-- A consumer owns its request history. Deleting the consumer must remove the
-- associated calls and their optional request/response diagnostics as well.
CREATE TABLE api_calls_with_consumer_delete (
    id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL,
    thread_id TEXT,
    consumer_id TEXT NOT NULL REFERENCES consumers(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(id),
    provider_id TEXT REFERENCES providers(id) ON DELETE SET NULL,
    affinity_hash TEXT,
    affinity_source TEXT,
    method TEXT NOT NULL,
    path TEXT NOT NULL,
    model TEXT,
    status INTEGER NOT NULL,
    first_byte_latency_ms INTEGER,
    latency_ms INTEGER NOT NULL,
    input_tokens INTEGER NOT NULL DEFAULT 0,
    output_tokens INTEGER NOT NULL DEFAULT 0,
    cached_tokens INTEGER NOT NULL DEFAULT 0,
    error TEXT,
    client_ip TEXT,
    created_at INTEGER NOT NULL
);

INSERT INTO api_calls_with_consumer_delete(
    id,request_id,thread_id,consumer_id,user_id,provider_id,affinity_hash,
    affinity_source,method,path,model,status,first_byte_latency_ms,latency_ms,
    input_tokens,output_tokens,cached_tokens,error,client_ip,created_at
)
SELECT
    id,request_id,thread_id,consumer_id,user_id,provider_id,affinity_hash,
    affinity_source,method,path,model,status,first_byte_latency_ms,latency_ms,
    input_tokens,output_tokens,cached_tokens,error,client_ip,created_at
FROM api_calls;

DROP TABLE api_calls;
ALTER TABLE api_calls_with_consumer_delete RENAME TO api_calls;

CREATE INDEX api_calls_consumer_time_idx ON api_calls(consumer_id, created_at DESC);
CREATE INDEX api_calls_user_time_idx ON api_calls(user_id, created_at DESC);
CREATE INDEX api_calls_affinity_time_idx ON api_calls(affinity_hash,created_at DESC);
CREATE INDEX api_calls_created_at_idx ON api_calls(created_at DESC);
CREATE INDEX api_calls_thread_time_idx ON api_calls(thread_id, created_at DESC);
