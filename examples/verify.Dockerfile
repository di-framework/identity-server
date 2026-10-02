FROM oven/bun:1

WORKDIR /verify
COPY verify.ts .
USER bun
CMD ["bun", "verify.ts"]
