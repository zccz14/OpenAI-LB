-- Reference images are encoded as data URLs in the authenticated console request.
-- Only migrate the historical default so an explicit operator override remains intact.
UPDATE app_meta
SET value = '16777216', updated_at = unixepoch()
WHERE key = 'image_body_limit' AND value = '4194304';
