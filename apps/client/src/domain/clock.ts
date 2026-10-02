export interface Clock {
  now(): number;
  hex(size: number): string;
}

export function systemClock(): Clock {
  return {
    now: () => Date.now(),
    hex: (size: number) => {
      const bytes = new Uint8Array(Math.ceil(size / 2));
      crypto.getRandomValues(bytes);
      return [...bytes]
        .map((value) => value.toString(16).padStart(2, '0'))
        .join('')
        .slice(0, size);
    },
  };
}

export function manualClock(start: number): Clock & { set(now: number): void } {
  let now = start;
  let sequence = 0;
  return {
    now: () => now,
    set: (value: number) => {
      now = value;
    },
    hex: (size: number) => {
      sequence += 1;
      return sequence.toString(16).padStart(size, '0').slice(-size);
    },
  };
}
