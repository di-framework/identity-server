/** Reads a JSON object supplied to an application command. */
export class JsonBody {
  constructor(private readonly value: Record<string, unknown>) {}

  text(key: string): string {
    const value = this.value[key];
    return typeof value === 'string' ? value.trim() : '';
  }

  optional(key: string): string | null {
    const value = this.text(key);
    return value.length > 0 ? value : null;
  }

  texts(key: string): string[] {
    const value = this.value[key];
    if (!Array.isArray(value)) return [];
    return value.filter((item) => typeof item === 'string');
  }

  flag(key: string): boolean {
    return this.value[key] === true;
  }
}
