CREATE TABLE provider_circuit_events (
    id TEXT PRIMARY KEY,
    provider_id TEXT NOT NULL REFERENCES providers(id) ON DELETE CASCADE,
    cause TEXT NOT NULL,
    rate_limit_json TEXT NOT NULL,
    opened_at INTEGER NOT NULL,
    cooldown_until INTEGER NOT NULL,
    closed_at INTEGER,
    resolution TEXT
);

CREATE INDEX provider_circuit_events_provider_time_idx
ON provider_circuit_events(provider_id, opened_at DESC);

CREATE UNIQUE INDEX provider_circuit_events_open_provider_idx
ON provider_circuit_events(provider_id) WHERE closed_at IS NULL;

-- A provider can be re-enabled by cooldown expiry, a credential update, or an
-- explicit operator action. The transition out of `cooldown` is the durable
-- boundary at which its open circuit event must be closed.
CREATE TRIGGER provider_circuit_events_close_on_status_change
AFTER UPDATE OF status ON providers
WHEN OLD.status = 'cooldown' AND NEW.status <> 'cooldown'
BEGIN
    UPDATE provider_circuit_events
    SET closed_at = NEW.updated_at,
        resolution = CASE
            WHEN NEW.status = 'active' THEN 'provider became active'
            ELSE 'provider status changed to ' || NEW.status
        END
    WHERE provider_id = NEW.id AND closed_at IS NULL;
END;

-- Preserve a cooldown that was already active when this version is installed.
INSERT INTO provider_circuit_events(
    id, provider_id, cause, rate_limit_json, opened_at, cooldown_until
)
SELECT
    lower(hex(randomblob(16))),
    id,
    COALESCE(last_error, 'rate limited'),
    COALESCE(rate_limit_json, '{}'),
    COALESCE(last_used_at, updated_at),
    cooldown_until
FROM providers
WHERE status = 'cooldown' AND cooldown_until IS NOT NULL;
