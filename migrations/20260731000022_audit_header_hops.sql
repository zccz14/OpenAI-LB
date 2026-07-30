ALTER TABLE request_archives ADD COLUMN upstream_request_headers_json TEXT;
ALTER TABLE request_archives ADD COLUMN downstream_response_headers_json TEXT;
