ALTER TABLE users ADD COLUMN system_role varchar(32) NOT NULL DEFAULT 'user';
ALTER TABLE organizations ADD COLUMN archived_at timestamptz;
