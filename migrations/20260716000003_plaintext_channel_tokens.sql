-- COMPATIBILITY: OpenAI-LB maintainers retain this migration while databases
-- created before 0.2.5 remain supported upgrade sources. The application
-- decrypts existing values once, then marks channel_tokens_plaintext=true.
-- Remove that conversion only after upgrading a preserved pre-0.2.5 fixture
-- is no longer part of the supported migration matrix.
ALTER TABLE channels RENAME COLUMN access_enc TO access_token;
ALTER TABLE channels RENAME COLUMN refresh_enc TO refresh_token;

INSERT INTO app_meta(key,value,updated_at)
VALUES('channel_tokens_plaintext','false',unixepoch());
