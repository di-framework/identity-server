import { expect, test } from 'bun:test';
import { resolve } from 'node:path';
import {
  coverageGaps,
  loadOpenApi,
  loadPlannedManifests,
  projectSurfaces,
} from '../src/codegen/contract.ts';

const root = resolve(import.meta.dir, '..');

test('GET /api/admin/users (operationId users) matches the projected admin HTTP surface', async () => {
  const spec = loadOpenApi(resolve(root, 'api/v1/openapi.yaml'));
  const projected = projectSurfaces(await loadPlannedManifests(root));
  expect(coverageGaps(spec, projected, ['users'])).toEqual([]);
});
