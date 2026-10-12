-- Browser sessions no longer hold secrets (identity-server#54). The client secret reveal moved to
-- an in-memory one-shot flash, and the identity link and unlink entries now keep only token hashes
-- under new names. Remove the old raw values from every existing session row. An UPDATE leaves the
-- old values in dead tuples, WAL and earlier backups until VACUUM and backup rotation.
UPDATE browser_sessions
SET attributes = attributes
  - 'IDENTITY_CLIENT_SECRET_REVEAL'
  - 'GSIO_IDENTITY_LINK_PENDING_TOKEN'
  - 'GSIO_IDENTITY_UNLINK_CONFIRMATION_TOKEN'
WHERE attributes
  - 'IDENTITY_CLIENT_SECRET_REVEAL'
  - 'GSIO_IDENTITY_LINK_PENDING_TOKEN'
  - 'GSIO_IDENTITY_UNLINK_CONFIRMATION_TOKEN' <> attributes;
