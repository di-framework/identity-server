CREATE TABLE oauth_client_lifecycle (
  client_id varchar(100) PRIMARY KEY REFERENCES oauth2_registered_client(client_id) ON DELETE RESTRICT,
  organization_slug varchar(128),
  created_at timestamptz NOT NULL DEFAULT now(),
  revoked_at timestamptz
);
