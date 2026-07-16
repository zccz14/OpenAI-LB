-- Existing API-call history must survive channel removal. The channel_id is
-- cleared because the referenced operational channel no longer exists.
CREATE TABLE api_calls_with_nullable_channel (
    id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL,
    api_key_id TEXT NOT NULL REFERENCES api_keys(id),
    user_id TEXT NOT NULL REFERENCES users(id),
    channel_id TEXT REFERENCES channels(id) ON DELETE SET NULL,
    method TEXT NOT NULL,
    path TEXT NOT NULL,
    model TEXT,
    status INTEGER NOT NULL,
    latency_ms INTEGER NOT NULL,
    input_tokens INTEGER NOT NULL DEFAULT 0,
    output_tokens INTEGER NOT NULL DEFAULT 0,
    cached_tokens INTEGER NOT NULL DEFAULT 0,
    error TEXT,
    client_ip TEXT,
    created_at INTEGER NOT NULL
);

INSERT INTO api_calls_with_nullable_channel(
    id,request_id,api_key_id,user_id,channel_id,method,path,model,status,
    latency_ms,input_tokens,output_tokens,cached_tokens,error,client_ip,created_at
)
SELECT
    id,request_id,api_key_id,user_id,channel_id,method,path,model,status,
    latency_ms,input_tokens,output_tokens,cached_tokens,error,client_ip,created_at
FROM api_calls;

DROP TABLE api_calls;
ALTER TABLE api_calls_with_nullable_channel RENAME TO api_calls;
CREATE INDEX api_calls_key_time_idx ON api_calls(api_key_id, created_at DESC);
CREATE INDEX api_calls_user_time_idx ON api_calls(user_id, created_at DESC);
