/**
 * A SQL fragment with `?` placeholders and the values they bind, in order. Fragments compose
 * through the `sql` tag, so a key only ever travels as a bound value: no code path puts it in
 * statement text.
 */
export class Sql {
  constructor(
    readonly text: string,
    readonly params: readonly unknown[],
  ) {}

  /** Trusted statement text (identifiers, keywords) with no bound values. */
  static raw(text: string): Sql {
    return new Sql(text, []);
  }

  static join(parts: readonly Sql[], separator: string): Sql {
    return new Sql(
      parts.map((part) => part.text).join(separator),
      parts.flatMap((part) => part.params),
    );
  }
}

/** Template tag: `Sql` values are spliced in, every other value becomes a `?` binding. */
export function sql(strings: TemplateStringsArray, ...values: unknown[]): Sql {
  let text = strings[0] ?? '';
  const params: unknown[] = [];
  values.forEach((value, index) => {
    if (value instanceof Sql) {
      text += value.text;
      params.push(...value.params);
    } else {
      text += '?';
      params.push(value);
    }
    text += strings[index + 1] ?? '';
  });
  return new Sql(text, params);
}
