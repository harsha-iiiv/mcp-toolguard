/**
 * Cheap, privacy-preserving value shapes. A shape never contains the raw value: only a character class
 * and a length bucket, e.g. "path:9-32" or "url:33-128". Non-string values become their JSON type.
 */

export type ValueClass =
  | 'empty'
  | 'number'
  | 'url'
  | 'email'
  | 'path'
  | 'base64'
  | 'hex'
  | 'word'
  | 'text'
  | 'multiline'
  | 'control';

const LENGTH_BUCKETS: readonly [number, string][] = [
  [0, '0'],
  [8, '1-8'],
  [32, '9-32'],
  [128, '33-128'],
  [512, '129-512'],
  [2048, '513-2048'],
];

export function lengthBucket(len: number): string {
  for (const [max, label] of LENGTH_BUCKETS) if (len <= max) return label;
  return '>2048';
}

const URL_RE = /^[a-z][a-z0-9+.-]*:\/\/\S+$/i;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const NUMBER_RE = /^[-+]?\d+(\.\d+)?([eE][-+]?\d+)?$/;
const PATH_PREFIX_RE = /^(~|\.{1,2})?[/\\]|^[A-Za-z]:[/\\]|^~$/;
const BASE64_RE = /^[A-Za-z0-9+/_-]+={0,2}$/;
const HEX_RE = /^(0x)?[0-9a-f]+$/i;
const FILENAME_RE = /^[\w.-]+\.[A-Za-z0-9]{1,8}$/;
// C0 controls other than \t \n \r, DEL, C1 controls, zero-width / bidi / Unicode tag characters.
// eslint-disable-next-line no-control-regex
const CONTROL_RE = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f​-‏‪-‮⁠-⁤⁦-⁩﻿]|\udb40[\udc00-\udc7f]/;

export function classifyString(s: string): ValueClass {
  if (s.length === 0) return 'empty';
  if (CONTROL_RE.test(s)) return 'control';
  const t = s.trim();
  if (t.length === 0) return 'text';
  if (/[\r\n]/.test(t)) return 'multiline';
  if (NUMBER_RE.test(t)) return 'number';
  if (URL_RE.test(t)) return 'url';
  if (EMAIL_RE.test(t)) return 'email';
  if (PATH_PREFIX_RE.test(t) && !/\s{2,}/.test(t)) return 'path';
  if (t.length >= 16 && HEX_RE.test(t)) return 'hex';
  if (t.length >= 20 && BASE64_RE.test(t) && /[A-Z]/.test(t) && /[a-z]/.test(t) && /\d/.test(t)) return 'base64';
  if (!/\s/.test(t) && (/[/\\]/.test(t) || FILENAME_RE.test(t))) return 'path';
  if (/\s/.test(t)) return 'text';
  return 'word';
}

/** Shape signature of a value: "<class>:<length bucket>" for strings, the JSON type otherwise. */
export function shapeOf(value: unknown): string {
  if (typeof value === 'string') return `${classifyString(value)}:${lengthBucket(value.length)}`;
  if (value === null) return 'null';
  if (Array.isArray(value)) return 'array';
  return typeof value; // number, boolean, object, ...
}

/** The class half of a shape signature. */
export function shapeClass(shape: string): string {
  const i = shape.indexOf(':');
  return i === -1 ? shape : shape.slice(0, i);
}
