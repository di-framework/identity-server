-- Browser sessions. The auth server keeps these in the servlet session (JSESSIONID); this
-- repository persists them so sign-in survives restarts and works across instances.
-- `id` is the SHA-256 hex of the cookie value; the cookie value itself is never stored.
CREATE TABLE browser_sessions (
  id char(64) PRIMARY KEY,
  user_id uuid REFERENCES users(id) ON DELETE CASCADE,
  csrf_token varchar(64) NOT NULL,
  last_authenticated_at timestamptz,
  attributes jsonb NOT NULL DEFAULT '{}',
  created_at timestamptz NOT NULL DEFAULT now(),
  last_seen_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL
);
CREATE INDEX browser_sessions_expires_at_idx ON browser_sessions (expires_at);
CREATE INDEX browser_sessions_user_id_idx ON browser_sessions (user_id);
