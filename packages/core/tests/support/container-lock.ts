const key = Symbol.for('identity.test.container-lock');

interface ContainerLock {
  tail: Promise<void>;
}

function containerLock(): ContainerLock {
  const registry = globalThis as typeof globalThis & Record<symbol, ContainerLock | undefined>;
  const existing = registry[key];
  if (existing) return existing;
  const created: ContainerLock = { tail: Promise.resolve() };
  registry[key] = created;
  return created;
}

const state = containerLock();

/** Serializes tests that replace the process-wide identity container. */
export function withContainer<T>(fn: () => Promise<T>): Promise<T> {
  const run = state.tail.then(fn, fn);
  state.tail = run.then(
    () => undefined,
    () => undefined,
  );
  return run;
}
