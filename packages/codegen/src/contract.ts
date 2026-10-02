/**
 * Compare an OpenAPI operation with the HTTP surface `@di-framework/codegen`
 * would emit, without running the generator.
 *
 * Planned manifests are the source of the projection. The spec is the source
 * of the expected method, path, status, response schema, and generated file.
 */
import { existsSync, readFileSync } from 'node:fs';
import { Glob, YAML } from 'bun';

const HTTP_METHODS = ['get', 'post', 'put', 'patch', 'delete', 'head', 'options'] as const;
type HttpMethod = (typeof HTTP_METHODS)[number];

export interface JsonSchema {
  [key: string]: unknown;
}

export interface PlannedSchema {
  jsonSchema: JsonSchema;
}

export interface PlannedHttp {
  method: string;
  path: string;
  successStatus?: number;
}

export interface PlannedOperation {
  input: string;
  output: string;
  http?: PlannedHttp;
}

/** Manifest shape this suite projects. Handlers are irrelevant to the spec comparison. */
export interface PlannedManifest {
  name: string;
  version: string;
  http?: { prefix?: string };
  schemas: Record<string, PlannedSchema>;
  operations: Record<string, PlannedOperation>;
}

export interface OperationContract {
  operationId: string;
  method: string;
  path: string;
  successStatus: number;
  generatedFile: string;
  controllerClass: string;
  responseSchema: JsonSchema;
  requestSchema?: JsonSchema;
}

export interface ProjectedSurface extends OperationContract {}

export interface ContractGap {
  operationId: string;
  expected: OperationContract;
  actual: ProjectedSurface | null;
  mismatches: string[];
}

interface OpenApiMedia {
  schema?: JsonSchema;
}

interface OpenApiOperation {
  operationId?: string;
  requestBody?: { content?: Record<string, OpenApiMedia> };
  responses?: Record<string, { content?: Record<string, OpenApiMedia> }>;
}

interface OpenApiDocument {
  paths: Record<string, Partial<Record<HttpMethod, OpenApiOperation>>>;
  components?: { schemas?: Record<string, JsonSchema> };
}

export function loadOpenApi(path: string): OpenApiDocument {
  const parsed: unknown = YAML.parse(readFileSync(path, 'utf8'));
  if (!isOpenApiDocument(parsed)) throw new Error(`${path} is not an OpenAPI document`);
  return parsed;
}

export async function loadPlannedManifests(root: string): Promise<PlannedManifest[]> {
  const dir = `${root}/src/contracts`;
  if (!existsSync(dir)) return [];

  const manifests: PlannedManifest[] = [];
  for (const file of new Glob('**/*.codegen.ts').scanSync({ cwd: dir, absolute: true })) {
    const imported = (await import(file)) as { default?: unknown };
    if (!isPlannedManifest(imported.default)) {
      throw new Error(`${file} default export is not a planned codegen manifest`);
    }
    manifests.push(imported.default);
  }
  return manifests;
}

/** Project the files and routes codegen would write for these manifests. */
export function projectSurfaces(
  manifests: readonly PlannedManifest[],
  outDir = 'src/generated',
): ProjectedSurface[] {
  const surfaces: ProjectedSurface[] = [];
  for (const manifest of manifests) {
    const generatedFile = `${outDir}/${manifest.name}/${manifest.version}/http.ts`;
    const controllerClass = controllerName(manifest.name, manifest.version);
    for (const [operationId, operation] of Object.entries(manifest.operations)) {
      if (!operation.http) continue;
      const output = manifest.schemas[operation.output];
      if (!output)
        throw new Error(
          `${manifest.name} operation ${operationId} is missing output schema ${operation.output}`,
        );
      const method = operation.http.method.toUpperCase();
      const request = manifest.schemas[operation.input];
      surfaces.push({
        operationId,
        method,
        path: joinRoute(manifest.http?.prefix, operation.http.path),
        successStatus: operation.http.successStatus ?? (method === 'POST' ? 201 : 200),
        generatedFile,
        controllerClass,
        responseSchema: output.jsonSchema,
        ...(request ? { requestSchema: request.jsonSchema } : {}),
      });
    }
  }
  return surfaces;
}

/**
 * Operations in `operationIds` whose projected surface does not match the spec.
 * An empty projection produces a `missing projected surface` gap.
 */
export function coverageGaps(
  doc: OpenApiDocument,
  surfaces: readonly ProjectedSurface[],
  operationIds: readonly string[],
  outDir = 'src/generated',
): ContractGap[] {
  const gaps: ContractGap[] = [];
  for (const operationId of operationIds) {
    const expected = contractForOperation(doc, operationId, outDir);
    const actual = surfaces.find((surface) => surface.operationId === operationId) ?? null;
    const mismatches = actual ? mismatchesBetween(expected, actual) : ['missing projected surface'];
    if (mismatches.length > 0) gaps.push({ operationId, expected, actual, mismatches });
  }
  return gaps;
}

export function contractForOperation(
  doc: OpenApiDocument,
  operationId: string,
  outDir = 'src/generated',
): OperationContract {
  for (const [path, item] of Object.entries(doc.paths)) {
    for (const method of HTTP_METHODS) {
      const operation = item[method];
      if (!operation || operation.operationId !== operationId) continue;
      const success = successResponse(operation);
      const identity = manifestIdentityForPath(path);
      const request = jsonSchema(operation.requestBody?.content?.['application/json']?.schema, doc);
      const responseSchema = jsonSchema(success.schema, doc) ?? {};
      return {
        operationId,
        method: method.toUpperCase(),
        path,
        successStatus: success.status,
        generatedFile: `${outDir}/${identity.name}/${identity.version}/http.ts`,
        controllerClass: controllerName(identity.name, identity.version),
        responseSchema,
        ...(request ? { requestSchema: request } : {}),
      };
    }
  }
  throw new Error(`OpenAPI operationId ${operationId} was not found`);
}

function mismatchesBetween(expected: OperationContract, actual: ProjectedSurface): string[] {
  const mismatches: string[] = [];
  if (actual.method !== expected.method)
    mismatches.push(`method ${actual.method} !== ${expected.method}`);
  if (actual.path !== expected.path) mismatches.push(`path ${actual.path} !== ${expected.path}`);
  if (actual.successStatus !== expected.successStatus) {
    mismatches.push(`successStatus ${actual.successStatus} !== ${expected.successStatus}`);
  }
  if (actual.generatedFile !== expected.generatedFile) {
    mismatches.push(`generatedFile ${actual.generatedFile} !== ${expected.generatedFile}`);
  }
  if (actual.controllerClass !== expected.controllerClass) {
    mismatches.push(`controllerClass ${actual.controllerClass} !== ${expected.controllerClass}`);
  }
  if (!sameJson(actual.responseSchema, expected.responseSchema))
    mismatches.push('responseSchema differs');
  if (expected.requestSchema && !sameJson(actual.requestSchema, expected.requestSchema))
    mismatches.push('requestSchema differs');
  return mismatches;
}

/** `/api/admin/*` is the admin v1 manifest. `/api/v1/{segment}` uses that segment as the manifest name. */
export function manifestIdentityForPath(path: string): { name: string; version: string } {
  if (path === '/api/admin' || path.startsWith('/api/admin/'))
    return { name: 'admin', version: 'v1' };
  if (path.startsWith('/api/v1/')) {
    const segment = path.split('/')[3];
    if (!segment) throw new Error(`OpenAPI path ${path} has no resource segment`);
    return { name: segment, version: 'v1' };
  }
  throw new Error(`no codegen manifest convention for ${path}`);
}

function successResponse(operation: OpenApiOperation): { status: number; schema: JsonSchema } {
  const status = Object.keys(operation.responses ?? {})
    .map((code) => Number(code))
    .filter((code) => code >= 200 && code < 300)
    .sort((left, right) => left - right)[0];
  if (status === undefined)
    throw new Error(`operation ${operation.operationId ?? '(unnamed)'} has no 2xx response`);
  const schema = operation.responses?.[String(status)]?.content?.['application/json']?.schema;
  if (!schema)
    throw new Error(
      `operation ${operation.operationId ?? '(unnamed)'} ${status} has no application/json schema`,
    );
  return { status, schema };
}

function jsonSchema(schema: JsonSchema | undefined, doc: OpenApiDocument): JsonSchema | undefined {
  if (!schema) return undefined;
  return dereference(schema, doc);
}

function dereference(schema: JsonSchema, doc: OpenApiDocument, stack: string[] = []): JsonSchema {
  const ref = schema.$ref;
  if (typeof ref === 'string') {
    if (stack.includes(ref)) throw new Error(`cyclic $ref ${ref}`);
    if (!ref.startsWith('#/components/schemas/')) throw new Error(`unsupported $ref ${ref}`);
    const name = ref.slice('#/components/schemas/'.length);
    const target = doc.components?.schemas?.[name];
    if (!target) throw new Error(`unresolved $ref ${ref}`);
    return dereference(target, doc, [...stack, ref]);
  }

  const resolved: JsonSchema = {};
  for (const [key, value] of Object.entries(schema))
    resolved[key] = dereferenceValue(value, doc, stack);
  return resolved;
}

function dereferenceValue(value: unknown, doc: OpenApiDocument, stack: string[]): unknown {
  if (Array.isArray(value)) return value.map((item) => dereferenceValue(item, doc, stack));
  if (isRecord(value)) return dereference(value, doc, stack);
  return value;
}

function joinRoute(prefix: string | undefined, path: string): string {
  if (!prefix) return path.startsWith('/') ? path : `/${path}`;
  const base = prefix.endsWith('/') ? prefix.slice(0, -1) : prefix;
  return `${base}${path.startsWith('/') ? path : `/${path}`}`;
}

function controllerName(name: string, version: string): string {
  return `${capitalize(name)}${capitalize(version)}HttpController`;
}

function capitalize(value: string): string {
  return value.length === 0 ? value : value.charAt(0).toUpperCase() + value.slice(1);
}

function sameJson(left: unknown, right: unknown): boolean {
  if (Object.is(left, right)) return true;
  if (Array.isArray(left) && Array.isArray(right)) {
    return (
      left.length === right.length && left.every((item, index) => sameJson(item, right[index]))
    );
  }
  if (!isRecord(left) || !isRecord(right)) return false;
  const leftKeys = Object.keys(left).sort();
  const rightKeys = Object.keys(right).sort();
  return (
    leftKeys.length === rightKeys.length &&
    leftKeys.every((key, index) => key === rightKeys[index] && sameJson(left[key], right[key]))
  );
}

function isOpenApiDocument(value: unknown): value is OpenApiDocument {
  return isRecord(value) && isRecord(value.paths);
}

function isPlannedManifest(value: unknown): value is PlannedManifest {
  if (!isRecord(value) || typeof value.name !== 'string' || typeof value.version !== 'string')
    return false;
  if (!isRecord(value.schemas) || !isRecord(value.operations)) return false;
  return true;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
