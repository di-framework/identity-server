/**
 * KubeInstance's diff, kept free of Pulumi so it can be tested without the engine
 * (deploy/guest/kube-diff.test.ts). index.ts passes `stateDir` and `existingKubeconfig` resolved
 * (absolute, empty as unset). An older state with a relative path or an empty string for the same
 * location is the same instance, not a replacement, which would run `kube down`.
 */

/** Inputs whose change means a different instance rather than an upgrade of this one. */
export const REPLACE_ON_CHANGE = ['name', 'stateDir', 'existingKubeconfig', 'existingContext'];
export const INPUT_KEYS = [
  ...REPLACE_ON_CHANGE,
  'version',
  'binary',
  'httpPort',
  'platformPackage',
  'platformConfig',
  'values',
  'allowInsecureRegistries',
  'purgeOnDelete',
];
const PATHS = ['stateDir', 'existingKubeconfig'];

export function kubeInstanceDiff(
  olds: Record<string, unknown>,
  news: Record<string, unknown>,
  resolvePath: (path: string) => string,
): { changes: boolean; replaces: string[]; deleteBeforeReplace: true } {
  const normal = (key: string, value: unknown) => {
    if (value === undefined || value === null || value === '') return undefined;
    return PATHS.includes(key) && typeof value === 'string' ? resolvePath(value) : value;
  };
  const differs = (key: string) =>
    JSON.stringify(normal(key, olds[key])) !== JSON.stringify(normal(key, news[key]));
  return {
    changes: INPUT_KEYS.some(differs),
    replaces: REPLACE_ON_CHANGE.filter(differs),
    deleteBeforeReplace: true,
  };
}
