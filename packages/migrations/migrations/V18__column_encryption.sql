-- Opt-in pgcrypto column encryption (identity-server#56, di-framework/platform#138).
--
-- This migration only prepares the schema; it encrypts nothing and changes no existing value.
-- Encryption starts when the operator sets IDENTITY_COLUMN_ENCRYPTION=enabled together with
-- IDENTITY_COLUMN_KEY and IDENTITY_BIDX_KEY (docs/configuration.md#column-encryption). The
-- service then latches `identity_column_encryption.enabled`, and from then on:
--   * new values go to `<column>_enc` (pgp_sym_encrypt) and the plaintext column is written NULL;
--   * looked-up values also get `<column>_bidx`, an HMAC-SHA256 blind index of the normalized value;
--   * rows written before that keep their plaintext. Reads return the decrypted ciphertext, else
--     the plaintext; lookups match the blind index or the plaintext. Plaintext also stays in WAL
--     and backups until a later re-encrypt pass.
-- Keys are always bound parameters. They are never stored here: only an HMAC check value per key,
-- so a process with a different key fails closed instead of writing data it cannot read back.

-- Engines without pgcrypto (the pglite provider before it ships the extension) still apply this
-- migration and run unencrypted; enabling encryption there fails closed.
DO $$
BEGIN
  CREATE EXTENSION IF NOT EXISTS pgcrypto;
EXCEPTION WHEN OTHERS THEN
  RAISE NOTICE 'pgcrypto is unavailable (%); column encryption cannot be enabled', SQLERRM;
END
$$;

CREATE TABLE identity_column_encryption (
  singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
  enabled boolean NOT NULL DEFAULT false,
  enabled_at timestamptz,
  column_key_check varchar(64),
  bidx_key_check varchar(64),
  CHECK (NOT enabled OR (enabled_at IS NOT NULL AND column_key_check IS NOT NULL
    AND bidx_key_check IS NOT NULL))
);
INSERT INTO identity_column_encryption (singleton) VALUES (true);
COMMENT ON TABLE identity_column_encryption IS
  'Opt-in column encryption state. enabled is one-way; the key checks are HMACs, not keys.';

-- users: email, display_name and avatar_url encrypted; normalized_email as a blind index.
ALTER TABLE users
  ADD COLUMN email_enc bytea,
  ADD COLUMN normalized_email_bidx bytea,
  ADD COLUMN display_name_enc bytea,
  ADD COLUMN avatar_url_enc bytea,
  ALTER COLUMN display_name DROP NOT NULL,
  ADD CONSTRAINT users_display_name_present
    CHECK (display_name IS NOT NULL OR display_name_enc IS NOT NULL) NOT VALID;
-- users_email_key stays: while disabled it keeps raw addresses unique even for a writer that leaves
-- normalized_email unset, and once enabled `email` is written NULL, which never collides. New rows
-- are unique by the blind index of the normalized address.
CREATE UNIQUE INDEX users_normalized_email_bidx_key ON users (normalized_email_bidx);

ALTER TABLE email_challenges
  ADD COLUMN email_enc bytea,
  ADD COLUMN email_bidx bytea,
  ALTER COLUMN email DROP NOT NULL,
  ADD CONSTRAINT email_challenges_email_present CHECK (email IS NOT NULL OR email_enc IS NOT NULL) NOT VALID;
CREATE INDEX email_challenges_rate_limit_bidx_idx
  ON email_challenges (email_bidx, purpose, created_at DESC);

ALTER TABLE identity_links
  ADD COLUMN subject_enc bytea,
  ADD COLUMN subject_bidx bytea,
  ADD COLUMN provider_email_enc bytea,
  ALTER COLUMN subject DROP NOT NULL,
  ADD CONSTRAINT identity_links_subject_present
    CHECK (subject IS NOT NULL OR subject_enc IS NOT NULL) NOT VALID,
  ADD CONSTRAINT uq_identity_links_issuer_subject_bidx UNIQUE (issuer, subject_bidx);

ALTER TABLE identity_link_flows
  ADD COLUMN nonce_enc bytea,
  ADD COLUMN code_verifier_enc bytea,
  ALTER COLUMN nonce DROP NOT NULL,
  ALTER COLUMN code_verifier DROP NOT NULL,
  ADD CONSTRAINT identity_link_flows_nonce_present CHECK (nonce IS NOT NULL OR nonce_enc IS NOT NULL) NOT VALID,
  ADD CONSTRAINT identity_link_flows_code_verifier_present
    CHECK (code_verifier IS NOT NULL OR code_verifier_enc IS NOT NULL) NOT VALID;

ALTER TABLE identity_unlink_confirmations
  ADD COLUMN subject_enc bytea,
  ALTER COLUMN subject DROP NOT NULL,
  ADD CONSTRAINT identity_unlink_confirmations_subject_present
    CHECK (subject IS NOT NULL OR subject_enc IS NOT NULL) NOT VALID;

ALTER TABLE identity_security_notifications ADD COLUMN recipient_email_enc bytea;

ALTER TABLE oauth2_authorization ADD COLUMN oidc_id_token_claims_enc bytea;

ALTER TABLE browser_sessions
  ADD COLUMN attributes_enc bytea,
  ALTER COLUMN attributes DROP NOT NULL,
  ADD CONSTRAINT browser_sessions_attributes_present
    CHECK (attributes IS NOT NULL OR attributes_enc IS NOT NULL) NOT VALID;

ALTER TABLE auth_audit_records
  ADD COLUMN before_metadata_enc bytea,
  ADD COLUMN after_metadata_enc bytea,
  ALTER COLUMN before_metadata DROP NOT NULL,
  ALTER COLUMN after_metadata DROP NOT NULL,
  ADD CONSTRAINT auth_audit_records_before_present
    CHECK (before_metadata IS NOT NULL OR before_metadata_enc IS NOT NULL) NOT VALID,
  ADD CONSTRAINT auth_audit_records_after_present
    CHECK (after_metadata IS NOT NULL OR after_metadata_enc IS NOT NULL) NOT VALID;

-- The CHECKs above are added NOT VALID: no scan of the existing rows here. V19 validates them in
-- its own migration (its own transaction on the guest), after this one commits.

-- The latch is one-way in the database, not only in the service: once enabled, the state row
-- cannot be turned off, have its key checks changed or cleared, be deleted, or be truncated
-- (SQLSTATE IDC02). An operator who really must undo it has to drop this trigger first, on purpose.
CREATE FUNCTION identity_column_encryption_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'TRUNCATE' OR TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'identity_column_encryption state cannot be removed' USING ERRCODE = 'IDC02';
  END IF;
  IF OLD.enabled AND (
    NOT NEW.enabled
    OR NEW.column_key_check IS DISTINCT FROM OLD.column_key_check
    OR NEW.bidx_key_check IS DISTINCT FROM OLD.bidx_key_check
  ) THEN
    RAISE EXCEPTION 'column encryption is enabled and cannot be turned off or rekeyed here'
      USING ERRCODE = 'IDC02';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER identity_column_encryption_guard_row BEFORE UPDATE OR DELETE
  ON identity_column_encryption FOR EACH ROW EXECUTE FUNCTION identity_column_encryption_guard();
CREATE TRIGGER identity_column_encryption_guard_truncate BEFORE TRUNCATE
  ON identity_column_encryption FOR EACH STATEMENT
  EXECUTE FUNCTION identity_column_encryption_guard();

-- Fail closed in the database too: while encryption is enabled, an INSERT or UPDATE that writes a
-- new non-NULL value to a protected plaintext column is refused (SQLSTATE IDC01). Updates that
-- leave a legacy row's plaintext unchanged are allowed.
CREATE FUNCTION identity_reject_plaintext() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
  written jsonb := to_jsonb(NEW);
  previous jsonb := CASE WHEN TG_OP = 'UPDATE' THEN to_jsonb(OLD) ELSE '{}'::jsonb END;
  column_name text;
BEGIN
  -- Recorded key checks count as enabled too, so clearing only `enabled` downgrades nothing.
  IF NOT EXISTS (
    SELECT 1 FROM identity_column_encryption
    WHERE enabled OR column_key_check IS NOT NULL OR bidx_key_check IS NOT NULL
  ) THEN
    RETURN NEW;
  END IF;
  FOREACH column_name IN ARRAY TG_ARGV LOOP
    IF jsonb_typeof(written -> column_name) <> 'null'
       AND (written -> column_name) IS DISTINCT FROM (previous -> column_name) THEN
      RAISE EXCEPTION 'column encryption is enabled; %.% must not be written in plaintext',
        TG_TABLE_NAME, column_name USING ERRCODE = 'IDC01';
    END IF;
  END LOOP;
  RETURN NEW;
END
$$;

CREATE TRIGGER users_reject_plaintext BEFORE INSERT OR UPDATE ON users
  FOR EACH ROW EXECUTE FUNCTION
  identity_reject_plaintext('email', 'normalized_email', 'display_name', 'avatar_url');
CREATE TRIGGER email_challenges_reject_plaintext BEFORE INSERT OR UPDATE ON email_challenges
  FOR EACH ROW EXECUTE FUNCTION identity_reject_plaintext('email');
CREATE TRIGGER identity_links_reject_plaintext BEFORE INSERT OR UPDATE ON identity_links
  FOR EACH ROW EXECUTE FUNCTION identity_reject_plaintext('subject', 'provider_email');
CREATE TRIGGER identity_link_flows_reject_plaintext BEFORE INSERT OR UPDATE ON identity_link_flows
  FOR EACH ROW EXECUTE FUNCTION identity_reject_plaintext('nonce', 'code_verifier');
CREATE TRIGGER identity_unlink_confirmations_reject_plaintext
  BEFORE INSERT OR UPDATE ON identity_unlink_confirmations
  FOR EACH ROW EXECUTE FUNCTION identity_reject_plaintext('subject');
CREATE TRIGGER identity_security_notifications_reject_plaintext
  BEFORE INSERT OR UPDATE ON identity_security_notifications
  FOR EACH ROW EXECUTE FUNCTION identity_reject_plaintext('recipient_email');
CREATE TRIGGER oauth2_authorization_reject_plaintext BEFORE INSERT OR UPDATE ON oauth2_authorization
  FOR EACH ROW EXECUTE FUNCTION identity_reject_plaintext('oidc_id_token_claims');
CREATE TRIGGER browser_sessions_reject_plaintext BEFORE INSERT OR UPDATE ON browser_sessions
  FOR EACH ROW EXECUTE FUNCTION identity_reject_plaintext('attributes');
CREATE TRIGGER auth_audit_records_reject_plaintext BEFORE INSERT OR UPDATE ON auth_audit_records
  FOR EACH ROW EXECUTE FUNCTION identity_reject_plaintext('before_metadata', 'after_metadata');
