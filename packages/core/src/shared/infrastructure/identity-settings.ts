import { deepMerge, envSource } from '@di-framework/config';
import { localPostgresUrl } from './database-config.ts';

/** One allowlisted external OpenID provider (`IDENTITY_IDENTITY_LINK__PROVIDERS`). */
export interface ProviderSettings {
  issuer?: string;
  authorizationEndpoint?: string;
  tokenEndpoint?: string;
  jwksUri?: string;
  clientId?: string;
  clientSecret?: string;
  scopes?: string[];
  freshAuthenticationParameter?: string;
}

export interface PersonSettings {
  email: string;
  login: string;
  displayName: string;
  password: string;
}

/**
 * Process settings. Names follow the auth server's `application.yml` env vars
 * (`ISSUER_URL`, `AUTH_*`, `SMTP_*`, `PORT`). `IDENTITY_*` double-underscore keys
 * (for example `IDENTITY_SERVER__HOST`) override any value.
 */
export interface IdentitySettings {
  server: { host: string; port: number };
  issuer: string;
  publicOrigin: string;
  cookieSecure: boolean;
  database: { url: string; poolMax: number };
  smtp: {
    host: string;
    port: number;
    username: string;
    password: string;
    from: string;
    auth: boolean;
    starttls: boolean;
    ssl: boolean;
  };
  jwk: { activePrivate: string; previousPublicSet: string; signingAlgorithm: string };
  bootstrap: {
    owner: PersonSettings;
    viewer: PersonSettings;
    organization: { slug: string; name: string };
  };
  clients: {
    access: { id: string; secret: string; redirectUris: string[] };
    directory: { id: string; secret: string };
    provisioner: { id: string; secret: string };
    /** Public native client (PKCE, no secret) for CLIs; registered only when `id` is set. */
    cli: { id: string; redirectUris: string[] };
  };
  identityLink: { clientId: string; providers: Record<string, ProviderSettings> };
  notifications: { fixedDelayMs: number; schedulerEnabled: boolean };
}

type Env = Record<string, string | undefined>;

export function loadIdentitySettings(env: Env = process.env): IdentitySettings {
  const text = (name: string, fallback = ''): string => env[name]?.trim() || fallback;
  const issuer = text('ISSUER_URL', 'http://localhost:4180');
  const base = {
    server: { host: '0.0.0.0', port: text('PORT', '4180') },
    issuer,
    publicOrigin: text('AUTH_PUBLIC_ORIGIN', issuer),
    cookieSecure: text('SERVER_SERVLET_SESSION_COOKIE_SECURE', 'true'),
    database: { url: text('DATABASE_URL', localPostgresUrl), poolMax: '8' },
    smtp: {
      host: text('SMTP_HOST'),
      port: text('SMTP_PORT', '587'),
      username: text('SMTP_USERNAME'),
      password: env.SMTP_PASSWORD ?? '',
      from: text('SMTP_FROM'),
      auth: text('SMTP_AUTH', 'true'),
      starttls: text('SMTP_STARTTLS', 'true'),
      ssl: text('SMTP_SSL_ENABLE', 'false'),
    },
    jwk: {
      activePrivate: text('AUTH_ACTIVE_PRIVATE_JWK'),
      previousPublicSet: text('AUTH_PREVIOUS_PUBLIC_JWK_SET'),
      signingAlgorithm: text('AUTH_SIGNING_ALGORITHM', 'RS256'),
    },
    bootstrap: {
      owner: person(env, 'AUTH_BOOTSTRAP_OWNER'),
      viewer: person(env, 'AUTH_BOOTSTRAP_VIEWER'),
      organization: {
        slug: text('AUTH_BOOTSTRAP_ORGANIZATION_SLUG'),
        name: text('AUTH_BOOTSTRAP_ORGANIZATION_NAME'),
      },
    },
    clients: {
      access: {
        id: text('AUTH_ACCESS_CLIENT_ID'),
        secret: env.AUTH_ACCESS_CLIENT_SECRET ?? '',
        redirectUris: text('AUTH_ACCESS_REDIRECT_URIS'),
      },
      directory: {
        id: text('AUTH_DIRECTORY_CLIENT_ID'),
        secret: env.AUTH_DIRECTORY_CLIENT_SECRET ?? '',
      },
      provisioner: {
        id: text('AUTH_PROVISIONER_CLIENT_ID'),
        secret: env.AUTH_PROVISIONER_CLIENT_SECRET ?? '',
      },
      cli: {
        id: text('AUTH_CLI_CLIENT_ID'),
        redirectUris: text('AUTH_CLI_REDIRECT_URIS', 'http://127.0.0.1/callback'),
      },
    },
    identityLink: {
      clientId: text('AUTH_IDENTITY_LINK_CLIENT_ID', 'gsio-auth-client'),
      providers: {},
    },
    notifications: {
      fixedDelayMs: text('GSIO_IDENTITY_NOTIFICATION_DELAY_MS', '5000'),
      schedulerEnabled: text('GSIO_IDENTITY_NOTIFICATION_SCHEDULER_ENABLED', 'true'),
    },
  };
  const overrides = envSource({ prefix: 'IDENTITY_', env, coerce: false }).load() as Record<
    string,
    unknown
  >;
  return normalize(deepMerge(base, overrides) as typeof base);
}

function person(env: Env, prefix: string): PersonSettings {
  return {
    email: env[`${prefix}_EMAIL`]?.trim() ?? '',
    login: env[`${prefix}_LOGIN`]?.trim() ?? '',
    displayName: env[`${prefix}_DISPLAY_NAME`]?.trim() ?? '',
    password: env[`${prefix}_PASSWORD`] ?? '',
  };
}

function normalize(raw: unknown): IdentitySettings {
  const value = raw as {
    server: { host: unknown; port: unknown };
    issuer: unknown;
    publicOrigin: unknown;
    cookieSecure: unknown;
    database: { url: unknown; poolMax: unknown };
    smtp: Record<string, unknown>;
    jwk: Record<string, unknown>;
    bootstrap: IdentitySettings['bootstrap'];
    clients: {
      access: { id: unknown; secret: unknown; redirectUris: unknown };
      directory: { id: unknown; secret: unknown };
      provisioner: { id: unknown; secret: unknown };
      cli: { id: unknown; redirectUris: unknown };
    };
    identityLink: { clientId: unknown; providers: unknown };
    notifications: { fixedDelayMs: unknown; schedulerEnabled: unknown };
  };
  return {
    server: { host: str(value.server.host), port: int(value.server.port, 'PORT') },
    issuer: str(value.issuer).replace(/\/+$/, ''),
    publicOrigin: str(value.publicOrigin).replace(/\/+$/, ''),
    cookieSecure: bool(value.cookieSecure),
    database: {
      url: str(value.database.url),
      poolMax: int(value.database.poolMax, 'database pool size'),
    },
    smtp: {
      host: str(value.smtp.host),
      port: int(value.smtp.port, 'SMTP_PORT'),
      username: str(value.smtp.username),
      password: str(value.smtp.password),
      from: str(value.smtp.from),
      auth: bool(value.smtp.auth),
      starttls: bool(value.smtp.starttls),
      ssl: bool(value.smtp.ssl),
    },
    jwk: {
      activePrivate: str(value.jwk.activePrivate),
      previousPublicSet: str(value.jwk.previousPublicSet),
      signingAlgorithm: str(value.jwk.signingAlgorithm),
    },
    bootstrap: value.bootstrap,
    clients: {
      access: {
        id: str(value.clients.access.id),
        secret: str(value.clients.access.secret),
        redirectUris: list(value.clients.access.redirectUris),
      },
      directory: {
        id: str(value.clients.directory.id),
        secret: str(value.clients.directory.secret),
      },
      provisioner: {
        id: str(value.clients.provisioner.id),
        secret: str(value.clients.provisioner.secret),
      },
      cli: {
        id: str(value.clients.cli.id),
        redirectUris: list(value.clients.cli.redirectUris),
      },
    },
    identityLink: {
      clientId: str(value.identityLink.clientId),
      providers: providers(value.identityLink.providers),
    },
    notifications: {
      fixedDelayMs: int(value.notifications.fixedDelayMs, 'GSIO_IDENTITY_NOTIFICATION_DELAY_MS'),
      schedulerEnabled: bool(value.notifications.schedulerEnabled),
    },
  };
}

function str(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

function bool(value: unknown): boolean {
  return str(value).toLowerCase() !== 'false';
}

function int(value: unknown, label: string): number {
  const parsed = Number(str(value));
  if (!Number.isInteger(parsed) || parsed < 0) throw new Error(`${label} must be an integer`);
  return parsed;
}

function list(value: unknown): string[] {
  return str(value)
    .split(',')
    .map((item) => item.trim())
    .filter((item) => item.length > 0);
}

/** Providers come from `IDENTITY_IDENTITY_LINK__PROVIDERS` (JSON) or nested `__` keys. */
function providers(value: unknown): Record<string, ProviderSettings> {
  let parsed: unknown = value;
  if (typeof value === 'string') {
    if (!value.trim()) return {};
    try {
      parsed = JSON.parse(value);
    } catch {
      throw new Error('Identity link providers must be a JSON object');
    }
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new Error('Identity link providers must be a JSON object');
  }
  const result: Record<string, ProviderSettings> = {};
  for (const [name, entry] of Object.entries(parsed as Record<string, unknown>)) {
    const record = (typeof entry === 'object' && entry !== null ? entry : {}) as Record<
      string,
      unknown
    >;
    const scopes = Array.isArray(record.scopes)
      ? record.scopes.filter((scope): scope is string => typeof scope === 'string')
      : typeof record.scopes === 'string'
        ? list(record.scopes)
        : undefined;
    result[name.toLowerCase()] = {
      issuer: optional(record.issuer),
      authorizationEndpoint: optional(record.authorizationEndpoint),
      tokenEndpoint: optional(record.tokenEndpoint),
      jwksUri: optional(record.jwksUri),
      clientId: optional(record.clientId),
      clientSecret: optional(record.clientSecret),
      scopes,
      freshAuthenticationParameter: optional(record.freshAuthenticationParameter),
    };
  }
  return result;
}

function optional(value: unknown): string | undefined {
  const text = str(value);
  return text ? text : undefined;
}
