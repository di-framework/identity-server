import { expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { generateOpenAPI } from '@di-framework/http';
import { YAML } from 'bun';
import { writeOpenApiSpec } from '../scripts/generate-openapi.ts';
import { Users } from '../src/contracts/api.schemas.ts';
import '../src/generated/account/v1/http.ts';
import '../src/generated/admin/v1/http.ts';
import '../src/generated/organizations/v1/http.ts';

const specPath = resolve(import.meta.dir, '../api/v1/openapi.yaml');

test('the generated OpenAPI document lists users from the endpoint metadata', () => {
  const source = YAML.parse(readFileSync(specPath, 'utf8')) as {
    paths: Record<string, Record<string, { operationId?: string; responses?: unknown }>>;
  };
  const users = source.paths['/api/admin/users']?.get;
  expect(users?.operationId).toBe('users');
  const responses = users?.responses as {
    '200'?: { content?: Record<string, { schema?: unknown }> };
  };
  expect(responses?.['200']?.content?.['application/json']?.schema).toEqual(Users.jsonSchema);

  const fresh = writeOpenApiSpec(join(tmpdir(), `identity-openapi-${process.pid}.yaml`));
  expect(readFileSync(fresh, 'utf8')).toBe(readFileSync(specPath, 'utf8'));
  expect(source.paths['/api/admin/users']?.post).toMatchObject({
    security: [{ oauth2: ['admin:write'] }],
  });
  expect(users).toMatchObject({ security: [{ oauth2: ['admin:read'] }] });
  expect(source.paths['/api/v1/organizations/{slug}/members']?.get).toMatchObject({
    security: [{ oauth2: ['directory:read'] }],
  });
  expect(source.paths['/api/v1/account/identity-links']?.get).not.toHaveProperty('security');
  const schemes = (source as { components?: { securitySchemes?: Record<string, unknown> } })
    .components?.securitySchemes;
  expect(schemes?.oauth2).toMatchObject({ type: 'oauth2' });
  expect(Object.keys(generateOpenAPI({ title: 't', version: 'v1' }).paths)).toEqual(
    Object.keys(source.paths),
  );
});
