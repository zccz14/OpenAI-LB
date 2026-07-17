CREATE TABLE request_archives (
    api_call_id TEXT PRIMARY KEY REFERENCES api_calls(id) ON DELETE CASCADE,
    request_headers_json TEXT NOT NULL,
    request_body BLOB NOT NULL,
    request_body_truncated INTEGER NOT NULL CHECK(request_body_truncated IN (0,1)),
    response_headers_json TEXT,
    response_body BLOB,
    response_body_truncated INTEGER NOT NULL CHECK(response_body_truncated IN (0,1)),
    created_at INTEGER NOT NULL
);
CREATE INDEX request_archives_created_at_idx ON request_archives(created_at);

INSERT INTO app_meta(key,value,updated_at)
VALUES('request_archive_retention_days','1',unixepoch());
