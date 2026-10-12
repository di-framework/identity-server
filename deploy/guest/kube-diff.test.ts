import { expect, test } from 'bun:test';
import { kubeInstanceDiff } from '../platform/components/kube-diff.ts';

const resolvePath = (path: string) =>
  path.startsWith('/') ? path : `/project/deploy/platform/${path.replace(/^\.\//, '')}`;
const base = { name: 'other', platformPackage: '@di-framework/platform@6.0.11' };

test('empty and relative spellings of the same location are the same instance', () => {
  // Empty strings in the old state against unset now: no change at all.
  expect(
    kubeInstanceDiff(
      { ...base, stateDir: '', existingKubeconfig: '', existingContext: '' },
      { ...base },
      resolvePath,
    ),
  ).toEqual({ changes: false, replaces: [], deleteBeforeReplace: true });
  // A relative path in the old state against its resolved absolute form now.
  expect(
    kubeInstanceDiff(
      { ...base, stateDir: './state', existingKubeconfig: 'kc' },
      {
        ...base,
        stateDir: '/project/deploy/platform/state',
        existingKubeconfig: '/project/deploy/platform/kc',
      },
      resolvePath,
    ),
  ).toEqual({ changes: false, replaces: [], deleteBeforeReplace: true });
});

test('a different state directory or kubeconfig is a different instance', () => {
  expect(
    kubeInstanceDiff({ ...base, stateDir: '/a' }, { ...base, stateDir: '/b' }, resolvePath)
      .replaces,
  ).toEqual(['stateDir']);
  expect(
    kubeInstanceDiff({ ...base }, { ...base, existingKubeconfig: 'kc' }, resolvePath).replaces,
  ).toEqual(['existingKubeconfig']);
  expect(
    kubeInstanceDiff(
      { ...base, existingContext: 'a' },
      { ...base, existingContext: 'b' },
      resolvePath,
    ).replaces,
  ).toEqual(['existingContext']);
  // An upgrade input changes without replacing.
  expect(
    kubeInstanceDiff(
      base,
      { ...base, platformPackage: '@di-framework/platform@6.0.12' },
      resolvePath,
    ),
  ).toEqual({ changes: true, replaces: [], deleteBeforeReplace: true });
});
