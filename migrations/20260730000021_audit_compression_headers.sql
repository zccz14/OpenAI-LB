ALTER TABLE api_calls ADD COLUMN downstream_accept_encoding TEXT;
ALTER TABLE api_calls ADD COLUMN downstream_content_encoding TEXT;
ALTER TABLE api_calls ADD COLUMN upstream_accept_encoding TEXT;
ALTER TABLE api_calls ADD COLUMN upstream_content_encoding TEXT;
