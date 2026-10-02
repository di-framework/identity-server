FROM debian:bookworm-slim

RUN useradd --system --no-create-home --shell /usr/sbin/nologin identity

COPY dist/identity-server /usr/local/bin/identity-server

USER identity
ENV PORT=4180
EXPOSE 4180
ENTRYPOINT ["/usr/local/bin/identity-server"]
