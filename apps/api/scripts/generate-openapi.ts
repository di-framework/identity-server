import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { generateOpenAPI } from '@di-framework/http';
import { YAML } from 'bun';
import '../src/generated/account/v1/http.ts';
import '../src/generated/admin/v1/http.ts';
import '../src/generated/organizations/v1/http.ts';

export const openApiSpecFile = resolve(import.meta.dir, '../api/v1/openapi.yaml');

/** Write the gitignored OpenAPI document from the generated @Endpoint routes. */
export function writeOpenApiSpec(path = openApiSpecFile): string {
  const document = generateOpenAPI({
    title: 'Identity Auth Control Plane API',
    version: 'v1',
    description: 'API for managing organizations, users, and OIDC clients.',
  });
  for (const methods of Object.values(document.paths)) {
    for (const operation of Object.values(methods)) {
      const operationId = operation.operationId;
      if (typeof operationId === 'string') {
        const method = operationId.slice(operationId.lastIndexOf('.') + 1);
        (operation as { operationId: string }).operationId = method;
      }
    }
  }
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, YAML.stringify(JSON.parse(JSON.stringify(document))));
  return path;
}

writeOpenApiSpec();
