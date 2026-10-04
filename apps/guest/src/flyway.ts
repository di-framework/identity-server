import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

export interface EmbeddedMigration {
  version: string;
  description: string;
  sql: string;
}

/** Read the Flyway directory. The guest bundle does not call this; it inlines the JSON snapshot. */
export function readFlywayMigrations(directory: string): EmbeddedMigration[] {
  return readdirSync(directory)
    .filter((name) => name.endsWith('.sql'))
    .map((name) => {
      const match = /^V(\d+)__(.+)\.sql$/.exec(name);
      if (!match || match[1] === undefined || match[2] === undefined) {
        throw new Error(`unexpected migration filename ${name}`);
      }
      return {
        version: String(Number(match[1])),
        description: match[2],
        sql: readFileSync(join(directory, name), 'utf8'),
      };
    })
    .sort((left, right) => Number(left.version) - Number(right.version));
}
