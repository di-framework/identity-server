import { expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { useContainer } from '@di-framework/core/container';
import { generateOpenAPIDocument } from '@di-framework/http';
import { YAML } from 'bun';
import { OpenApiCatalog } from '../src/identity/http/control-plane.ts';

const METHODS = ['get', 'post', 'put', 'patch', 'delete'] as const;

test('emitted OpenAPI matches the JSON control plane', async () => {
  const source = YAML.parse(readFileSync(resolve('api/v1/openapi.yaml'), 'utf8')) as {
    info: { title: string; version: string; description: string };
    paths: Record<string, Record<string, Record<string, unknown>>>;
    components: { schemas: Record<string, unknown> };
  };
  const catalog = useContainer().resolve(OpenApiCatalog);
  const { document } = await generateOpenAPIDocument({
    controllerModules: [resolve('src/identity/http/control-plane.ts')],
    configuration: {
      title: source.info.title,
      version: source.info.version,
      description: source.info.description,
      schemas: source.components.schemas,
    },
  });

  const expectedPaths: Record<string, Record<string, unknown>> = {};
  for (const [path, item] of Object.entries(source.paths)) {
    if (!path.startsWith('/api/')) continue;
    for (const method of METHODS) {
      const operation = item[method];
      if (!operation || !isJson(operation)) continue;
      const operationId = String(operation.operationId);
      expectedPaths[path] ??= {};
      expectedPaths[path][method] = {
        ...operation,
        operationId: `ControlPlaneController.${operationId}`,
        summary: operation.summary ?? operationId,
      };
      delete (expectedPaths[path][method] as { tags?: unknown }).tags;
    }
  }

  expect(catalog.operations).toHaveLength(
    Object.values(expectedPaths).reduce((count, item) => count + Object.keys(item).length, 0),
  );
  expect(json(document.info)).toEqual(json(source.info));
  expect(json(document.paths)).toEqual(json(expectedPaths));
  expect(json(document.components.schemas)).toEqual(json(source.components.schemas));
});

function isJson(operation: Record<string, unknown>): boolean {
  const responses = operation.responses as
    | Record<string, { content?: Record<string, unknown> }>
    | undefined;
  for (const [code, response] of Object.entries(responses ?? {})) {
    const status = Number(code);
    if (status < 200 || status >= 300) continue;
    if (response.content?.['application/json']) return true;
    if (status === 204 && !response.content) return true;
  }
  return false;
}

function json(value: unknown): unknown {
  return JSON.parse(JSON.stringify(value));
}
