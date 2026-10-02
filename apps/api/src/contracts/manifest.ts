const handlerModule = '../handlers.ts';

interface HttpOperation {
  method: string;
  path: string;
  successStatus?: number;
  summary?: string;
  description?: string;
  parameters?: ReadonlyArray<Record<string, unknown>>;
}

interface ManifestOperation {
  input: string;
  output: string;
  handler: { module: string; export: string; method: string };
  http?: HttpOperation;
}

export const idempotency = {
  name: 'Idempotency-Key',
  in: 'header',
  required: false,
  schema: { type: 'string' },
};

export function queryParameter(
  name: string,
  schema: Record<string, unknown>,
  required = false,
): Record<string, unknown> {
  return { name, in: 'query', required, schema };
}

export function operation(
  name: string,
  http: HttpOperation,
  input: string,
  output: string,
): [string, ManifestOperation] {
  return [
    name,
    {
      input,
      output,
      handler: { module: handlerModule, export: 'ControlPlaneHandlers', method: name },
      http,
    },
  ];
}

export function manifest(
  name: string,
  prefix: string,
  schemas: Record<
    string,
    {
      schema: { parse(input: unknown): unknown; jsonSchema: Record<string, unknown> };
      module: string;
    }
  >,
  operations: Array<[string, ManifestOperation]>,
) {
  return {
    name,
    version: 'v1',
    http: { prefix },
    schemas,
    operations: Object.fromEntries(operations),
  };
}
