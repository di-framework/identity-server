CREATE TABLE oauth_refresh_token_history (
  token_hash char(64) PRIMARY KEY,
  authorization_id varchar(100) NOT NULL,
  expires_at timestamptz NOT NULL,
  reused_at timestamptz
);
CREATE INDEX oauth_refresh_token_history_authorization_idx ON oauth_refresh_token_history (authorization_id);
