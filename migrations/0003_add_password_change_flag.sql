-- Migration number: 0003 	 2025-01-XX
-- Add must_change_password flag to users table

ALTER TABLE users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0;

CREATE INDEX IF NOT EXISTS idx_users_must_change_password ON users(must_change_password);

