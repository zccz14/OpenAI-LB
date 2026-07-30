ALTER TABLE api_calls
ADD COLUMN request_transport_bytes INTEGER NOT NULL DEFAULT 0;

ALTER TABLE api_calls
ADD COLUMN response_transport_bytes INTEGER NOT NULL DEFAULT 0;
