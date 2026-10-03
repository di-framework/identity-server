/** Time source for expiry, rate limits, and step-up windows. Tests swap in a manual clock. */
export interface Clock {
  now(): number;
}

export function systemClock(): Clock {
  return { now: () => Date.now() };
}

export function manualClock(
  start: number,
): Clock & { set(now: number): void; advance(ms: number): void } {
  let now = start;
  return {
    now: () => now,
    set: (value: number) => {
      now = value;
    },
    advance: (ms: number) => {
      now += ms;
    },
  };
}
