-- Runtime secrets moved out of the database: the wasmCloud guest now reads them from its
-- `identity-control` Kubernetes Secret through the WASI environment. Remove any copies the
-- earlier guest stored here. The table keeps only the guest's bootstrap state (the settings
-- fingerprints and the reconcile lease), none of which is secret.
DELETE FROM identity_runtime_secret
WHERE name IN (
  'ISSUER_URL',
  'AUTH_PUBLIC_ORIGIN',
  'AUTH_ACTIVE_PRIVATE_JWK',
  'AUTH_PREVIOUS_PUBLIC_JWK_SET',
  'SMTP_HOST',
  'SMTP_USERNAME',
  'SMTP_PASSWORD',
  'AUTH_ACCESS_REDIRECT_URIS',
  'AUTH_BOOTSTRAP_OWNER_PASSWORD',
  'AUTH_BOOTSTRAP_VIEWER_PASSWORD',
  'AUTH_ACCESS_CLIENT_SECRET',
  'AUTH_DIRECTORY_CLIENT_SECRET',
  'AUTH_PROVISIONER_CLIENT_SECRET',
  'AUTH_CLI_CLIENT_ID',
  'AUTH_CLI_REDIRECT_URIS'
);

COMMENT ON TABLE identity_runtime_secret IS
  'wasmCloud guest bootstrap state (fingerprints, reconcile lease). Not for secrets.';
