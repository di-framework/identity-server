-- Browser sessions no longer hold secrets (identity-server#54). The client secret is shown once in
-- the response that mints it, and the identity link and unlink entries now keep only token hashes
-- under new names. Remove the old raw values from every existing session row. Rows whose
-- attributes are not a JSON object are left alone (`-` would fail on a scalar). An UPDATE leaves
-- the old values in dead tuples, WAL and earlier backups until VACUUM and backup rotation.
UPDATE browser_sessions
SET attributes = attributes
  - 'IDENTITY_CLIENT_SECRET_REVEAL'
  - 'GSIO_IDENTITY_LINK_PENDING_TOKEN'
  - 'GSIO_IDENTITY_UNLINK_CONFIRMATION_TOKEN'
WHERE jsonb_typeof(attributes) = 'object'
  AND attributes ?| ARRAY[
    'IDENTITY_CLIENT_SECRET_REVEAL',
    'GSIO_IDENTITY_LINK_PENDING_TOKEN',
    'GSIO_IDENTITY_UNLINK_CONFIRMATION_TOKEN'
  ];
