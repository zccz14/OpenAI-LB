ALTER TABLE users
ADD COLUMN display_name_overridden INTEGER NOT NULL DEFAULT 0 CHECK(display_name_overridden IN (0,1));
