ALTER TABLE consumers
ADD COLUMN request_archive INTEGER NOT NULL DEFAULT 0 CHECK(request_archive IN (0,1));
