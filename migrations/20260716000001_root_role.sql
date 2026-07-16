-- COMPATIBILITY: OpenAI-LB maintainers retain this migration because 0.1
-- databases allowed only admin/user. It can be removed only when 0.1 is no
-- longer a supported upgrade source; verify removal by upgrading a preserved
-- 0.1 fixture through the new minimum supported schema.
CREATE TABLE users_with_root (
    id TEXT PRIMARY KEY,
    email TEXT,
    display_name TEXT,
    role TEXT NOT NULL CHECK(role IN ('root','admin','user')),
    created_at INTEGER NOT NULL
);
INSERT INTO users_with_root(id,email,display_name,role,created_at)
SELECT id,email,display_name,role,created_at FROM users;
DROP TABLE users;
ALTER TABLE users_with_root RENAME TO users;
CREATE UNIQUE INDEX users_single_root ON users(role) WHERE role='root';
