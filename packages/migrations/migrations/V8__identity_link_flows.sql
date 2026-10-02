CREATE TABLE identity_link_flows (
    token_hash CHAR(64) PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_hash CHAR(64) NOT NULL,
    provider_name VARCHAR(128) NOT NULL,
    issuer VARCHAR(512) NOT NULL,
    nonce VARCHAR(128) NOT NULL,
    code_verifier VARCHAR(128) NOT NULL,
    code_challenge VARCHAR(128) NOT NULL,
    return_url VARCHAR(2048) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE INDEX idx_identity_link_flows_expiry ON identity_link_flows(expires_at);
