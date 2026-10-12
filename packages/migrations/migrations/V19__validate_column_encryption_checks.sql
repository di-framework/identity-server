-- Validates the presence CHECKs V18 added NOT VALID (identity-server#56). VALIDATE CONSTRAINT
-- scans each table under SHARE UPDATE EXCLUSIVE, which does not block reads or writes, and runs
-- as its own migration so V18's ACCESS EXCLUSIVE ALTERs are already committed. Every existing
-- row passes: its plaintext column was NOT NULL before V18.
ALTER TABLE users VALIDATE CONSTRAINT users_display_name_present;
ALTER TABLE email_challenges VALIDATE CONSTRAINT email_challenges_email_present;
ALTER TABLE identity_links VALIDATE CONSTRAINT identity_links_subject_present;
ALTER TABLE identity_link_flows VALIDATE CONSTRAINT identity_link_flows_nonce_present;
ALTER TABLE identity_link_flows VALIDATE CONSTRAINT identity_link_flows_code_verifier_present;
ALTER TABLE identity_unlink_confirmations VALIDATE CONSTRAINT identity_unlink_confirmations_subject_present;
ALTER TABLE browser_sessions VALIDATE CONSTRAINT browser_sessions_attributes_present;
ALTER TABLE auth_audit_records VALIDATE CONSTRAINT auth_audit_records_before_present;
ALTER TABLE auth_audit_records VALIDATE CONSTRAINT auth_audit_records_after_present;
