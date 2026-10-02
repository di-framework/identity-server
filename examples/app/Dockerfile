FROM debian:bookworm-slim

RUN useradd --system --no-create-home --shell /usr/sbin/nologin app

COPY dist/example-app /usr/local/bin/example-app

USER app
ENV PORT=3000
EXPOSE 3000
ENTRYPOINT ["/usr/local/bin/example-app"]
