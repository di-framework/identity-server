import { expect, test } from 'bun:test';
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  contractForOperation,
  coverageGaps,
  loadOpenApi,
  loadPlannedManifests,
  manifestIdentityForPath,
  type PlannedManifest,
  projectSurfaces,
} from '../src/codegen/contract.ts';

const itemDoc = {
  paths: {
    '/api/admin/items': {
      post: {
        operationId: 'makeItem',
        requestBody: {
          content: { 'application/json': { schema: { $ref: '#/components/schemas/Item' } } },
        },
        responses: {
          '201': { content: { 'application/json': { schema: { type: 'string' } } } },
          '200': {
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  required: ['id', 'name'],
                  properties: { tags: { enum: ['a', 'b'] } },
                },
              },
            },
          },
        },
      },
    },
  },
  components: { schemas: { Item: { type: 'object', properties: { name: { type: 'string' } } } } },
};

test('projects manifest conventions and reports contract gaps', () => {
  const surfaces = projectSurfaces([
    {
      name: '',
      version: 'v1',
      schemas: { Out: { jsonSchema: { type: 'string' } } },
      operations: {
        skipped: { input: 'Out', output: 'Out' },
        plain: { input: 'Missing', output: 'Out', http: { method: 'GET', path: 'plain' } },
        rooted: { input: 'Missing', output: 'Out', http: { method: 'GET', path: '/rooted' } },
      },
    },
    {
      name: 'orders',
      version: 'v1',
      http: { prefix: '/v1/' },
      schemas: {
        Out: { jsonSchema: { type: 'string' } },
        In: { jsonSchema: { type: 'number' } },
      },
      operations: {
        made: { input: 'In', output: 'Out', http: { method: 'post', path: 'made' } },
      },
    },
    {
      name: 'files',
      version: 'v1',
      http: { prefix: '/files' },
      schemas: { Out: { jsonSchema: { type: 'string' } } },
      operations: {
        read: {
          input: 'Out',
          output: 'Out',
          http: { method: 'GET', path: '/read', successStatus: 200 },
        },
      },
    },
  ] satisfies PlannedManifest[]);
  expect(
    surfaces.map((surface) => [surface.operationId, surface.path, surface.successStatus]),
  ).toEqual([
    ['plain', '/plain', 200],
    ['rooted', '/rooted', 200],
    ['made', '/v1/made', 201],
    ['read', '/files/read', 200],
  ]);
  expect(surfaces[0]?.controllerClass).toBe('V1HttpController');
  expect(() =>
    projectSurfaces([
      {
        name: 'demo',
        version: 'v1',
        schemas: {},
        operations: {
          ping: { input: 'Missing', output: 'Missing', http: { method: 'GET', path: '/ping' } },
        },
      },
    ]),
  ).toThrow('missing output schema');

  expect(manifestIdentityForPath('/api/admin')).toEqual({ name: 'admin', version: 'v1' });
  expect(manifestIdentityForPath('/api/admin/users')).toEqual({ name: 'admin', version: 'v1' });
  expect(manifestIdentityForPath('/api/v1/organizations/{slug}/members')).toEqual({
    name: 'organizations',
    version: 'v1',
  });
  expect(() => manifestIdentityForPath('/api/v1/')).toThrow('no resource segment');
  expect(() => manifestIdentityForPath('/health')).toThrow('no codegen manifest convention');

  const expected = contractForOperation(itemDoc, 'makeItem');
  expect(expected.successStatus).toBe(200);
  expect(coverageGaps(itemDoc, [], ['makeItem'])[0]?.mismatches).toEqual([
    'missing projected surface',
  ]);
  const wrong = {
    ...expected,
    method: 'GET',
    path: '/nope',
    successStatus: 500,
    generatedFile: 'nope.ts',
    controllerClass: 'Nope',
    responseSchema: { type: 'number' },
    requestSchema: { type: 'number' },
  };
  expect(coverageGaps(itemDoc, [wrong], ['makeItem'])[0]?.mismatches).toEqual([
    'method GET !== POST',
    'path /nope !== /api/admin/items',
    'successStatus 500 !== 200',
    'generatedFile nope.ts !== src/generated/admin/v1/http.ts',
    'controllerClass Nope !== AdminV1HttpController',
    'responseSchema differs',
    'requestSchema differs',
  ]);
  const copied = {
    ...expected,
    method: 'GET',
    responseSchema: structuredClone(expected.responseSchema),
    requestSchema: structuredClone(expected.requestSchema),
  };
  expect(coverageGaps(itemDoc, [copied], ['makeItem'])[0]?.mismatches).toEqual([
    'method GET !== POST',
  ]);
  expect(() => contractForOperation(itemDoc, 'missing')).toThrow('was not found');
});

test('rejects openapi documents and manifests that cannot be projected', async () => {
  const root = mkdtempSync(join(tmpdir(), 'identity-contract-'));
  writeFileSync(join(root, 'openapi.yaml'), 'title: nope\n');
  expect(() => loadOpenApi(join(root, 'openapi.yaml'))).toThrow('not an OpenAPI document');
  expect(await loadPlannedManifests(root)).toEqual([]);

  const invalid = mkdtempSync(join(tmpdir(), 'identity-manifest-'));
  const contracts = join(invalid, 'src/contracts');
  mkdirSync(contracts, { recursive: true });
  await Bun.write(join(contracts, 'bad.codegen.ts'), 'export default 1;\n');
  await expect(loadPlannedManifests(invalid)).rejects.toThrow('not a planned codegen manifest');

  const partial = mkdtempSync(join(tmpdir(), 'identity-partial-'));
  const partialContracts = join(partial, 'src/contracts');
  mkdirSync(partialContracts, { recursive: true });
  await Bun.write(
    join(partialContracts, 'partial.codegen.ts'),
    'export default { name: "demo", version: "v1", schemas: [], operations: {} };\n',
  );
  await expect(loadPlannedManifests(partial)).rejects.toThrow('not a planned codegen manifest');

  const cyclic = {
    paths: {
      '/api/admin/loop': {
        get: {
          operationId: 'loop',
          responses: {
            '200': {
              content: { 'application/json': { schema: { $ref: '#/components/schemas/Loop' } } },
            },
          },
        },
      },
    },
    components: { schemas: { Loop: { $ref: '#/components/schemas/Loop' } } },
  };
  expect(() => contractForOperation(cyclic, 'loop')).toThrow('cyclic $ref');
  const unsupported = {
    paths: {
      '/api/admin/ref': {
        get: {
          operationId: 'ref',
          responses: {
            '200': {
              content: { 'application/json': { schema: { $ref: '#/components/parameters/Ref' } } },
            },
          },
        },
      },
    },
  };
  expect(() => contractForOperation(unsupported, 'ref')).toThrow('unsupported $ref');
  const unresolved = {
    paths: {
      '/api/admin/missing': {
        get: {
          operationId: 'missingRef',
          responses: {
            '200': {
              content: { 'application/json': { schema: { $ref: '#/components/schemas/Missing' } } },
            },
          },
        },
      },
    },
    components: { schemas: {} },
  };
  expect(() => contractForOperation(unresolved, 'missingRef')).toThrow('unresolved $ref');
  expect(() =>
    contractForOperation(
      { paths: { '/api/admin/none': { get: { responses: { '400': {} } } } } },
      undefined as never,
    ),
  ).toThrow('(unnamed)');
  expect(() =>
    contractForOperation(
      {
        paths: {
          '/api/admin/plain': {
            get: {
              operationId: 'plain',
              responses: { '200': { content: { 'text/plain': { schema: { type: 'string' } } } } },
            },
          },
        },
      },
      'plain',
    ),
  ).toThrow('no application/json schema');
});
