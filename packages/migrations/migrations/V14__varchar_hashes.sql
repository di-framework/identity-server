-- wasmcloud:postgres@0.2.0 fails to decode bpchar (`char(n)`) result values.
-- These columns hold exact hex strings, so varchar keeps the same data.
ALTER TABLE browser_sessions
  ALTER COLUMN id TYPE varchar(64) USING rtrim(id)::varchar(64);
ALTER TABLE email_challenges
  ALTER COLUMN token_hash TYPE varchar(64) USING rtrim(token_hash)::varchar(64),
  ALTER COLUMN request_ip_hash TYPE varchar(64) USING rtrim(request_ip_hash)::varchar(64);
ALTER TABLE oauth_refresh_token_history
  ALTER COLUMN token_hash TYPE varchar(64) USING rtrim(token_hash)::varchar(64);
ALTER TABLE identity_link_flows
  ALTER COLUMN token_hash TYPE varchar(64) USING rtrim(token_hash)::varchar(64),
  ALTER COLUMN session_hash TYPE varchar(64) USING rtrim(session_hash)::varchar(64);
ALTER TABLE identity_unlink_confirmations
  ALTER COLUMN token_hash TYPE varchar(64) USING rtrim(token_hash)::varchar(64),
  ALTER COLUMN session_hash TYPE varchar(64) USING rtrim(session_hash)::varchar(64);
ALTER TABLE identity_security_notifications
  ALTER COLUMN event_key TYPE varchar(64) USING rtrim(event_key)::varchar(64);
