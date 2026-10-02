FROM debian:bookworm-slim

RUN useradd --system --no-create-home --shell /usr/sbin/nologin identity

COPY dist/identity-server /usr/local/bin/identity-server

USER identity
# Required at runtime (see docs/configuration.md): DATABASE_URL, ISSUER_URL, AUTH_PUBLIC_ORIGIN,
# AUTH_ACTIVE_PRIVATE_JWK, SMTP_*, AUTH_BOOTSTRAP_*, AUTH_ACCESS_*, AUTH_DIRECTORY_*,
# AUTH_PROVISIONER_*. The container serves HTTP; terminate TLS at the edge and probe GET /ready.
ENV PORT=4180
EXPOSE 4180
ENTRYPOINT ["/usr/local/bin/identity-server"]
