/**
 * Invisible-character analysis for the `hidden-unicode` rule.
 *
 * Flagged classes:
 *  - zero-width: U+200B ZWSP, U+200C ZWNJ, U+200D ZWJ, U+2060 WORD JOINER, U+FEFF ZWNBSP/BOM
 *  - bidi:       U+202A–U+202E (LRE RLE PDF LRO RLO), U+2066–U+2069 (LRI RLI FSI PDI)
 *  - tag:        U+E0000–U+E007F (Unicode "tag" block; maps 1:1 onto ASCII → "ASCII smuggling")
 *
 * Legitimate uses that are deliberately NOT flagged:
 *  - a single U+FEFF at the very start of a string (byte-order mark from a file read);
 *  - ZWJ / ZWNJ between two emoji (👨‍👩‍👧) or between two non-ASCII letters/marks (Persian, Indic
 *    scripts, where ZWNJ/ZWJ are orthographically required);
 *  - emoji subdivision flags: U+1F3F4 followed by tag letters/digits and U+E007F (🏴󠁧󠁢󠁳󠁣󠁴󠁿).
 */

export type HiddenKind = 'zero-width' | 'bidi' | 'tag';

export interface HiddenScan {
  counts: Record<HiddenKind, number>;
  /** Distinct code points seen, as "U+XXXX". */
  codepoints: string[];
  /** ASCII text decoded from tag characters (empty if none). */
  decodedTags: string;
  /** Index (UTF-16) of the first flagged character, or -1. */
  firstIndex: number;
}

const ZERO_WIDTH = new Set([0x200b, 0x200c, 0x200d, 0x2060, 0xfeff]);
const JOINERS = new Set([0x200c, 0x200d]);
const EMOJI_NEIGHBOUR = /[\p{Extended_Pictographic}\p{Emoji_Modifier}\u{FE0F}\u{20E3}]/u;
const NON_ASCII_LETTER = /[\p{L}\p{M}]/u;

function isBidi(cp: number): boolean {
  return (cp >= 0x202a && cp <= 0x202e) || (cp >= 0x2066 && cp <= 0x2069);
}
function isTag(cp: number): boolean {
  return cp >= 0xe0000 && cp <= 0xe007f;
}

/** Quick pre-filter so the common case (plain text) costs one regex test. */
const ANY_SUSPICIOUS = /[\u200B-\u200D\u2060\uFEFF\u202A-\u202E\u2066-\u2069\u{E0000}-\u{E007F}]/u;

export function scanHidden(text: string): HiddenScan | undefined {
  if (!ANY_SUSPICIOUS.test(text)) return undefined;
  const cps = Array.from(text);
  const counts: Record<HiddenKind, number> = { 'zero-width': 0, bidi: 0, tag: 0 };
  const seen = new Set<string>();
  let decoded = '';
  let firstIndex = -1;
  let utf16 = 0;
  let inFlagSeq = false;

  const legitJoiner = (i: number): boolean => {
    const prev = cps[i - 1];
    const next = cps[i + 1];
    if (!prev || !next) return false;
    if (EMOJI_NEIGHBOUR.test(prev) && EMOJI_NEIGHBOUR.test(next)) return true;
    const nonAscii = (c: string) => c.codePointAt(0)! > 0x7f && NON_ASCII_LETTER.test(c);
    return nonAscii(prev) && nonAscii(next);
  };

  for (let i = 0; i < cps.length; i++) {
    const ch = cps[i]!;
    const cp = ch.codePointAt(0)!;
    const at = utf16;
    utf16 += ch.length;

    if (cp === 0x1f3f4) {
      inFlagSeq = true;
      continue;
    }
    let kind: HiddenKind | undefined;
    if (isTag(cp)) {
      // Emoji subdivision flag: 🏴 + tag [a-z0-9]+ + CANCEL TAG.
      if (inFlagSeq) {
        const ascii = cp - 0xe0000;
        if (cp === 0xe007f) {
          inFlagSeq = false;
          continue;
        }
        if ((ascii >= 0x61 && ascii <= 0x7a) || (ascii >= 0x30 && ascii <= 0x39)) continue;
      }
      kind = 'tag';
      const ascii = cp - 0xe0000;
      if (ascii >= 0x20 && ascii < 0x7f) decoded += String.fromCharCode(ascii);
    } else {
      inFlagSeq = false;
      if (ZERO_WIDTH.has(cp)) {
        if (cp === 0xfeff && i === 0) continue;
        if (JOINERS.has(cp) && legitJoiner(i)) continue;
        kind = 'zero-width';
      } else if (isBidi(cp)) {
        kind = 'bidi';
      }
    }
    if (!kind) continue;
    counts[kind]++;
    seen.add(`U+${cp.toString(16).toUpperCase().padStart(4, '0')}`);
    if (firstIndex < 0) firstIndex = at;
  }

  if (firstIndex < 0) return undefined;
  return { counts, codepoints: [...seen], decodedTags: decoded, firstIndex };
}

/** Replace every invisible / control character with a visible ⟦U+XXXX⟧ marker. */
export function revealHidden(text: string): string {
  return text.replace(
    /[​-‍⁠﻿‪-‮⁦-⁩]|[\u{E0000}-\u{E007F}]+/gu,
    (m) => {
      const first = m.codePointAt(0)!;
      if (isTag(first)) return '⟦tags⟧';
      return `⟦U+${first.toString(16).toUpperCase().padStart(4, '0')}⟧`;
    },
  );
}

/**
 * Text as the model effectively reads it, for phrase matching: NFKC (folds fullwidth/compat
 * letters such as "ｉｇｎｏｒｅ"), with invisible and bidi characters removed so that
 * "ig\u200Bnore previous instructions" still matches. Tag characters are removed here; callers
 * scan the decoded tag text separately (see `withHiddenText`).
 */
export function normalizeForMatching(text: string): string {
  return text.normalize('NFKC').replace(/[\u00AD\u200B-\u200F\u2060-\u2064\uFEFF\u202A-\u202E\u2066-\u2069\u{E0000}-\u{E007F}]/gu, '');
}

/**
 * Normalised copies of `hits`, plus one extra hit per string whose Unicode-tag payload decodes to
 * ASCII (the "ASCII smuggling" channel), so phrase rules see what the model sees.
 */
export function withHiddenText<T extends { path: string; value: string }>(hits: readonly T[]): T[] {
  const out: T[] = [];
  for (const h of hits) {
    out.push({ ...h, value: normalizeForMatching(h.value) });
    const scan = scanHidden(h.value);
    if (scan?.decodedTags) out.push({ ...h, path: `${h.path}`, value: scan.decodedTags });
  }
  return out;
}
