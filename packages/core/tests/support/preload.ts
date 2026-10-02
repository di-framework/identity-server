import { rsaPrivateJwk } from './keys.ts';

/**
 * Test process settings. The identity settings factory reads `process.env` lazily, so these
 * values are what every container-resolved service sees under `bun test`.
 */
process.env.AUTH_ACTIVE_PRIVATE_JWK ||= JSON.stringify(rsaPrivateJwk('test-active'));
process.env.ISSUER_URL ||= 'https://identity.test';
process.env.GSIO_IDENTITY_NOTIFICATION_SCHEDULER_ENABLED ||= 'false';
