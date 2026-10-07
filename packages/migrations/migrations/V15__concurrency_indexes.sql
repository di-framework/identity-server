CREATE INDEX IF NOT EXISTS oauth2_authorization_code_idx
  ON oauth2_authorization (authorization_code_value)
  WHERE authorization_code_value IS NOT NULL;

CREATE INDEX IF NOT EXISTS oauth2_authorization_state_idx
  ON oauth2_authorization (state)
  WHERE state IS NOT NULL;
