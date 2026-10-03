import { writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { readFlywayMigrations } from '../src/flyway.ts';

const guest = dirname(import.meta.dir);
const directory = join(guest, '..', '..', 'packages/migrations/migrations');
const migrations = readFlywayMigrations(directory);
writeFileSync(join(guest, 'src/migrations.json'), `${JSON.stringify(migrations, null, 2)}\n`);
