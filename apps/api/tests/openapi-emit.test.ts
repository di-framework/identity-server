import { expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { generateOpenAPI } from '@di-framework/http';
import { YAML } from 'bun';
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

  const document = generateOpenAPI({
    title: 'Identity Auth Control Plane API',
    version: 'v1',
    description: 'API for managing organizations, users, and OIDC clients.',
  });
  for (const methods of Object.values(document.paths)) {
    for (const operation of Object.values(methods)) {
      const operationId = operation.operationId;
      if (typeof operationId === 'string') {
        (operation as { operationId: string }).operationId = operationId.slice(
          operationId.lastIndexOf('.') + 1,
        );
      }
    }
  }
  expect(JSON.parse(JSON.stringify(document.paths))).toEqual(source.paths);
});
