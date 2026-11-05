-- Token audiences an admin-registered OAuth client is issued for (identity-server#48).
-- Comma-separated like the Spring list columns; empty means the client id is the only audience.
ALTER TABLE oauth_client_lifecycle ADD COLUMN audiences varchar(1000) NOT NULL DEFAULT '';
