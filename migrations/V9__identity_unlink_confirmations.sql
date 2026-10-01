CREATE TABLE identity_unlink_confirmations (
    token_hash CHAR(64) PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_hash CHAR(64) NOT NULL,
    issuer VARCHAR(512) NOT NULL,
    subject VARCHAR(512) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE INDEX idx_identity_unlink_confirmations_expiry
    ON identity_unlink_confirmations(expires_at);
CREATE INDEX idx_identity_unlink_confirmations_user_session
    ON identity_unlink_confirmations(user_id, session_hash, created_at DESC);
