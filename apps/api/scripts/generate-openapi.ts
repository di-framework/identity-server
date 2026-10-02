import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { generateOpenAPI } from '@di-framework/http';
import { YAML } from 'bun';
import { requiredScope } from '../src/guards/bearer-guard.ts';
import { schemas } from '../src/schemas.ts';
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
  for (const [path, methods] of Object.entries(document.paths)) {
    for (const [verb, operation] of Object.entries(methods)) {
      const operationId = operation.operationId;
      if (typeof operationId === 'string') {
        const method = operationId.slice(operationId.lastIndexOf('.') + 1);
        (operation as { operationId: string }).operationId = method;
      }
      const scope = requiredScope(verb.toUpperCase(), path);
      if (scope) (operation as { security?: unknown }).security = [{ oauth2: [scope] }];
    }
  }
  const withComponents = document as { components?: Record<string, unknown> };
  withComponents.components = { ...withComponents.components };
  // Endpoint schemas reference these by `#/components/schemas/<name>`; publish them so the
  // document is self-contained (`openapi-typescript` refuses dangling references).
  withComponents.components.schemas = {
    ...(withComponents.components.schemas as Record<string, unknown> | undefined),
    ...schemas,
  };
  withComponents.components.securitySchemes = {
    oauth2: {
      type: 'oauth2',
      description: 'Opaque access token from the client-credentials grant.',
      flows: {
        clientCredentials: {
          tokenUrl: '/oauth2/token',
          scopes: {
            'admin:read': 'Read users, organizations, memberships, clients, and audit records.',
            'admin:write': 'Change users, organizations, memberships, and clients.',
            'directory:read': 'Page through organization members.',
          },
        },
      },
    },
  };
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, YAML.stringify(JSON.parse(JSON.stringify(document))));
  return path;
}

writeOpenApiSpec();
