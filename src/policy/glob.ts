/**
 * Minimal glob → RegExp. Only '*' (any run of characters, including none) and '?' (exactly one
 * character) are special. Everything else is matched literally. The pattern is anchored.
 */
export function globToRegExp(glob: string): RegExp {
  let src = '';
  for (const ch of glob) {
    if (ch === '*') src += '.*';
    else if (ch === '?') src += '.';
    else src += ch.replace(/[.+^${}()|[\]\\/-]/g, '\\$&');
  }
  return new RegExp(`^${src}$`, 's');
}

export function compileGlobs(globs: readonly string[]): RegExp[] {
  return globs.map(globToRegExp);
}

export function matchesAny(name: string, patterns: readonly RegExp[]): boolean {
  return patterns.some((re) => re.test(name));
}
