/**
 * Database drivers attach the statement and its bound values to errors: PGlite's `DatabaseError`
 * carries `query` and `params`, others `parameters`. Column encryption binds its keys, so those
 * fields can hold a key or plaintext PII. Remove them before an error is logged or rethrown.
 */
const STATEMENT_FIELDS = ['params', 'parameters', 'query', 'values'] as const;

/**
 * Removes statement text and bound values from `error` and its `cause` chain, in place. An error
 * whose fields cannot be removed is replaced by a plain one with only its message and code.
 */
export function redactStatement(error: unknown): unknown {
  let current: unknown = error;
  for (let depth = 0; depth < 8 && typeof current === 'object' && current !== null; depth++) {
    const record = current as Record<string, unknown>;
    for (const field of STATEMENT_FIELDS) {
      if (field in record && !Reflect.deleteProperty(record, field)) return replacement(error);
    }
    current = record.cause;
  }
  return error;
}

function replacement(error: unknown): Error {
  const { code, errno } = error as { code?: unknown; errno?: unknown };
  return Object.assign(new Error((error as { message?: unknown }).message as string), {
    code,
    errno,
  });
}

/** What may be logged about a failure: its message and code, never statement values. */
export function describeError(error: unknown): string {
  if (!(error instanceof Error)) return 'unknown error';
  const code = (error as { code?: unknown }).code;
  return typeof code === 'string' && code ? `${error.message} (${code})` : error.message;
}
