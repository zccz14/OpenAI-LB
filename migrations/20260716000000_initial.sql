CREATE TABLE IF NOT EXISTS app_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT,
    display_name TEXT,
    role TEXT NOT NULL CHECK(role IN ('root','admin','user')),
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS api_keys (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    prefix TEXT NOT NULL,
    secret_hash TEXT NOT NULL UNIQUE,
    created_at INTEGER NOT NULL,
    last_used_at INTEGER,
    revoked_at INTEGER
);
CREATE INDEX IF NOT EXISTS api_keys_user_idx ON api_keys(user_id, created_at DESC);

CREATE TABLE IF NOT EXISTS channels (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    account_id TEXT NOT NULL,
    access_enc TEXT NOT NULL,
    refresh_enc TEXT NOT NULL,
    expires_at INTEGER,
    status TEXT NOT NULL DEFAULT 'active',
    manual_disabled INTEGER NOT NULL DEFAULT 0,
    cooldown_until INTEGER,
    rate_limit_json TEXT,
    last_error TEXT,
    last_used_at INTEGER,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS channels_available_idx ON channels(manual_disabled, status, cooldown_until);

CREATE TABLE IF NOT EXISTS oauth_flows (
    state_hash TEXT PRIMARY KEY,
    verifier_enc TEXT NOT NULL,
    created_by TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS affinities (
    affinity_hash TEXT PRIMARY KEY,
    channel_id TEXT NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
    expires_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS affinities_expiry_idx ON affinities(expires_at);

CREATE TABLE IF NOT EXISTS api_calls (
    id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL,
    api_key_id TEXT NOT NULL REFERENCES api_keys(id),
    user_id TEXT NOT NULL REFERENCES users(id),
    channel_id TEXT REFERENCES channels(id),
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
CREATE INDEX IF NOT EXISTS api_calls_key_time_idx ON api_calls(api_key_id, created_at DESC);
CREATE INDEX IF NOT EXISTS api_calls_user_time_idx ON api_calls(user_id, created_at DESC);

CREATE TABLE IF NOT EXISTS admin_audit (
    id TEXT PRIMARY KEY,
    admin_user_id TEXT NOT NULL REFERENCES users(id),
    action TEXT NOT NULL,
    target_id TEXT,
    client_ip TEXT,
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS admin_audit_time_idx ON admin_audit(created_at DESC);

INSERT OR IGNORE INTO app_meta(key,value,updated_at) VALUES
    ('setup_complete','false',unixepoch()),
    ('auth_issuer','',unixepoch()),
    ('auth_audience','',unixepoch()),
    ('upstream_base','https://chatgpt.com/backend-api/codex',unixepoch()),
    ('image_host_model','gpt-5.4',unixepoch()),
    ('oauth_authorize_url','https://auth.openai.com/oauth/authorize',unixepoch()),
    ('oauth_token_url','https://auth.openai.com/oauth/token',unixepoch()),
    ('oauth_redirect_uri','http://localhost:1455/auth/callback',unixepoch()),
    ('oauth_client_id','app_EMoamEEZ73f0CkXaXp7hrann',unixepoch()),
    ('response_body_limit','2097152',unixepoch()),
    ('image_body_limit','4194304',unixepoch()),
    ('audio_body_limit','536870912',unixepoch()),
    ('affinity_ttl_seconds','86400',unixepoch());
