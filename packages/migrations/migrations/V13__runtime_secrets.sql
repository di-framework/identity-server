-- Guest runtime settings that cannot travel in wasi:config (private keys, passwords, and URLs).
CREATE TABLE identity_runtime_secret (
  name varchar(128) PRIMARY KEY,
  value text NOT NULL
);
