-- Runtime secrets moved out of the database: the wasmCloud guest now reads them from its
-- `identity-control` Kubernetes Secret through the WASI environment. Keep only the guest's
-- bootstrap state (the settings fingerprints and the reconcile lease, none of it secret) and
-- remove every other row, including any written by hand under other names.
--
-- On a Postgres database from the earlier guest (authproto's `directory`), these rows may be the
-- only copy of the signing key and client secrets: export them before this migration runs there
-- (docs/guest-http-api.md#authproto-cutover). A DELETE leaves the values in dead tuples, WAL and
-- earlier backups until VACUUM and backup rotation.
DELETE FROM identity_runtime_secret
WHERE name NOT IN ('bootstrap_fingerprint', 'bootstrap_client_fingerprints', 'bootstrap_lease');

COMMENT ON TABLE identity_runtime_secret IS
  'wasmCloud guest bootstrap state (fingerprints, reconcile lease). Not for secrets.';
