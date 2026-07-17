UPDATE app_meta
SET value = '1', updated_at = unixepoch()
WHERE key = 'request_archive_retention_days' AND value = '7';
