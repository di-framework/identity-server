import { expect, test } from 'bun:test';
import { resolve } from 'node:path';
import {
  coverageGaps,
  loadOpenApi,
  loadPlannedManifests,
  projectSurfaces,
} from '../src/contract.ts';
import { listUsers } from '../src/contracts/admin-v1.codegen.ts';

const packageRoot = resolve(import.meta.dir, '..');
const specPath = resolve(import.meta.dir, '../../../apps/api/api/v1/openapi.yaml');

test('listUsers starts empty', () => {
  expect(listUsers()).toEqual([]);
});

test('GET /api/admin/users (operationId users) matches the projected admin HTTP surface', async () => {
  const spec = loadOpenApi(specPath);
  const projected = projectSurfaces(await loadPlannedManifests(packageRoot));
  expect(coverageGaps(spec, projected, ['users'])).toEqual([]);
});
