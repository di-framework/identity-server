# Admin API: OAuth clients

`/api/admin/oauth-clients` registers the OAuth clients of a tenant (an organization). The
routes need an opaque bearer token with `admin:read` (reads) or `admin:write` (writes); see
[Configuration](configuration.md#endpoints). Every client registered here belongs to an
organization. The only global clients are the bootstrap clients from configuration
(`AUTH_ACCESS_*`, `AUTH_DIRECTORY_*`, `AUTH_PROVISIONER_*`, `AUTH_CLI_*`), which the reconciler
owns.

| Method and path | Purpose | Status |
| --- | --- | --- |
| `GET /api/admin/oauth-clients` | List every client, revoked ones included. | 200 |
| `POST /api/admin/oauth-clients` | Register a client. `Idempotency-Key` makes the create replayable. | 201 |
| `GET /api/admin/oauth-clients/{clientId}` | One client. | 200, 404 |
| `PUT /api/admin/oauth-clients/{clientId}` | Replace the client's metadata. | 200, 400, 404, 409 |
| `POST /api/admin/oauth-clients/{clientId}/rotate-secret` | Issue a new secret for a confidential client. | 200, 400, 404, 409 |
| `DELETE /api/admin/oauth-clients/{clientId}` | Revoke the client. The id stays taken. | 204, 404 |

## Request (`CreateOAuthClientRequest`, `UpdateOAuthClientRequest`)

| Field | Required | Meaning |
| --- | --- | --- |
| `clientId` | create | 1 to 100 characters, trimmed. Also the stored client name. The update path parameter names the client. |
| `organizationSlug` | yes | The tenant the client belongs to, 1 to 128 characters. A missing or blank slug is a 400. The slug is not checked against the organization directory; `DELETE /api/admin/organizations/{slug}` refuses while the organization has an active client. |
| `redirectUris` | for `browser` and public clients | Exact-match redirect URIs. A public client's must all be loopback `http` URIs (`http://127.0.0.1/...` or `http://[::1]/...`); the port is matched at authorize time (RFC 8252 section 7.3). |
| `scopes` | no | Scopes the client may request. |
| `audiences` | no | Token `aud` values (see below). Each value is a non-empty string without whitespace or commas; the stored list is at most 1000 characters. Duplicates are dropped. |
| `browser` | no | `true` registers `authorization_code` plus `refresh_token` with PKCE and consent; `false` (the default) registers `client_credentials`. A public client is always a browser client. |
| `tokenEndpointAuthMethod` | no | `client_secret_basic` (the default) registers a confidential client; `none` a public PKCE client. Fixed at registration: an update that names the other method is a 409. |

Lists are compared as sets; unknown fields are ignored.

## Response (`OAuthClientResponse`)

```json
{
  "client_id": "tenant-acme-0a1b2c3d-cli",
  "organization_slug": "acme",
  "redirect_uris": ["http://127.0.0.1/callback"],
  "scopes": ["openid", "profile"],
  "audiences": ["https://acme.example.com"],
  "browser": true,
  "token_endpoint_auth_method": "none",
  "revoked_at": null,
  "created_at": "2026-11-05T12:00:00.000Z"
}
```

`POST` and `rotate-secret` answer with `OAuthClientSecretResponse`: `{ "client_id": "...",
"client_secret": "..." }` for a confidential client and `{ "client_id": "..." }` for a public one.
The secret is shown once; only its Argon2id hash is stored.

## Audiences

`audiences` are the `aud` values the client's tokens carry:

- Introspection (`POST /oauth2/introspect`, RFC 7662) reports `aud` as the configured audiences,
  or `[client_id]` when none are configured.
- An ID token's `aud` is the client id followed by the configured audiences: OpenID Connect
  requires the relying party among the audiences, so the client id is never dropped.

Bootstrap and HTML-registered clients have no audiences unless the registered-client
repository sets them; their tokens carry the client id alone.

## Public PKCE clients

`tokenEndpointAuthMethod: "none"` registers the shape the bootstrap CLI client has: no secret,
`authorization_code` and `refresh_token`, PKCE and consent required, loopback redirects only.
The token endpoint accepts such a client with `client_id` and a `code_verifier`, as the
bootstrap CLI client is accepted; introspection stays confidential-only (RFC 7662). `rotate-secret`
on a public client is a 409, and `browser` is implied.

## Idempotency

`POST` with an `Idempotency-Key` derives the secret from the key (see
`docs/internal/parity.md`), so a repeated create returns the same secret. The key is bound to the
client it created: a replay with the same metadata answers 201 again, a replay that asks for a
different client (another id, organization, method, redirect URIs, scopes, or audiences) is a
409, and an id that already exists, revoked or not, is a 409 without a matching key.

The client and its idempotency record (the `admin.oauth_client_created` audit row) are written
in one transaction. Two concurrent keyed creates of the same client therefore end with one 201
each: the loser of the unique-index race waits for the winner to commit, then replays the
record. On a database that runs every statement on its own (the wasmCloud guest), the loser
can still answer 409 in that window; the caller re-reads the client and carries on.

`rotate-secret` with an `Idempotency-Key` derives the secret from the key and `version`, so
repeating a rotation returns the same secret and a new version a new one.

## Pulumi

The `gas` provider's `OAuthClient` resource takes the same fields (`organizationSlug`
required, `audiences`, `tokenEndpointAuthMethod`); see `packages/provider/README.md`.
