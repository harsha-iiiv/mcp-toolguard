import { describe, expect, it } from 'vitest';
import { redactSecrets } from '../../../src/audit/index.js';

// Test secrets are assembled at runtime so source scanners don't flag this file.
const j = (...parts: string[]): string => parts.join('');

const SAMPLES: Array<[kind: string, secret: string]> = [
  ['aws-access-key', j('AKIA', 'IOSFODNN7EXAMPLE')],
  ['aws-access-key', j('ASIA', 'ABCDEFGHIJKLMNOP')],
  ['github-token', j('ghp_', 'a'.repeat(36))],
  ['github-token', j('gho_', 'B1'.repeat(18))],
  ['github-token', j('ghs_', 'c'.repeat(36))],
  ['github-token', j('github_pat_', '11ABCDEFG0', 'x'.repeat(60))],
  ['openai-key', j('sk-', 'A1b2'.repeat(10))],
  ['openai-key', j('sk-proj-', 'Zz9_-'.repeat(10))],
  ['anthropic-key', j('sk-ant-', 'api03-', 'Q'.repeat(80))],
  ['slack-token', j('xoxb-', '123456789012-', 'abcdefABCDEF')],
  ['slack-token', j('xoxp-', '1234-5678-abcdefgh')],
  ['google-api-key', j('AIza', 'SyD-'.padEnd(35, 'k'))],
  ['stripe-key', j('sk_live_', '4eC39HqLyjWDarjtT1zdp7dc')],
  ['stripe-key', j('rk_live_', '4eC39HqLyjWDarjtT1zdp7dc')],
  [
    'jwt',
    j('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9', '.', 'eyJzdWIiOiIxMjM0NTY3ODkwIn0', '.', 'dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U'),
  ],
];

describe('redactSecrets: patterns', () => {
  for (const [kind, secret] of SAMPLES) {
    it(`redacts ${kind} (${secret.slice(0, 8)}...)`, () => {
      const out = redactSecrets({ body: `please send ${secret} to bob` });
      expect(out.body).toBe(`please send [REDACTED:${kind}] to bob`);
      expect(JSON.stringify(out)).not.toContain(secret);
    });
  }

  it('anthropic keys are not labelled as openai', () => {
    const out = redactSecrets(j('sk-ant-', 'x'.repeat(40)));
    expect(out).toBe('[REDACTED:anthropic-key]');
  });

  it('replaces a whole PEM private key block', () => {
    const pem = [
      j('-----BEGIN RSA ', 'PRIVATE KEY-----'),
      'MIIEpAIBAAKCAQEA1234567890abcdef',
      'qwertyuiopasdfghjkl+/=',
      j('-----END RSA ', 'PRIVATE KEY-----'),
    ].join('\n');
    const out = redactSecrets(`before\n${pem}\nafter`);
    expect(out).toBe('before\n[REDACTED:private-key]\nafter');
  });

  it('handles OPENSSH and plain PKCS#8 blocks and a truncated block', () => {
    const openssh = j('-----BEGIN OPENSSH ', 'PRIVATE KEY-----\nb3BlbnNzaA==\n-----END OPENSSH ', 'PRIVATE KEY-----');
    const plain = j('-----BEGIN ', 'PRIVATE KEY-----\nMIIE\n-----END ', 'PRIVATE KEY-----');
    expect(redactSecrets(`${openssh} and ${plain}`)).toBe('[REDACTED:private-key] and [REDACTED:private-key]');
    const truncated = j('key: -----BEGIN EC ', 'PRIVATE KEY-----\nMHcCAQEEIBb');
    expect(redactSecrets(truncated)).toBe('key: [REDACTED:private-key]');
  });

  it('leaves ordinary text alone', () => {
    const v = { msg: 'hello world, skip this, ask-me, AKIA-not-a-key', n: 42, ok: true, nil: null };
    expect(redactSecrets(v)).toEqual(v);
  });

  it('redacts inside arrays and nested objects', () => {
    const key = j('AKIA', 'IOSFODNN7EXAMPLE');
    const out = redactSecrets({ a: [{ b: [`x ${key}`] }] });
    expect(out).toEqual({ a: [{ b: ['x [REDACTED:aws-access-key]'] }] });
  });
});

describe('redactSecrets: key names', () => {
  it('redacts non-empty string values of sensitive keys (case-insensitive)', () => {
    const out = redactSecrets({
      password: 'hunter2',
      DB_PASSWD: 'x',
      clientSecret: 'abc',
      access_token: 'tok',
      apiKey: 'k1',
      'x-api-key': 'k2',
      API_KEY: 'k3',
      Authorization: 'Bearer abc',
      Cookie: 'sid=1',
      private_key: 'pk',
      privateKey: 'pk2',
      username: 'alice',
    });
    expect(out).toEqual({
      password: '[REDACTED:password]',
      DB_PASSWD: '[REDACTED:password]',
      clientSecret: '[REDACTED:secret]',
      access_token: '[REDACTED:token]',
      apiKey: '[REDACTED:api-key]',
      'x-api-key': '[REDACTED:api-key]',
      API_KEY: '[REDACTED:api-key]',
      Authorization: '[REDACTED:authorization]',
      Cookie: '[REDACTED:cookie]',
      private_key: '[REDACTED:private-key]',
      privateKey: '[REDACTED:private-key]',
      username: 'alice',
    });
  });

  it('keeps empty strings and non-string values of sensitive keys', () => {
    const out = redactSecrets({ password: '', token: 123, secret: null, cookie: { name: 'plain' } });
    expect(out).toEqual({ password: '', token: 123, secret: null, cookie: { name: 'plain' } });
  });
});

describe('redactSecrets: structure', () => {
  it('replaces cycles with [Circular]', () => {
    const a: Record<string, unknown> = { name: 'a' };
    a.self = a;
    a.list = [a, { back: a }];
    const out = redactSecrets(a) as Record<string, unknown>;
    expect(out).toEqual({ name: 'a', self: '[Circular]', list: ['[Circular]', { back: '[Circular]' }] });
    expect(() => JSON.stringify(out)).not.toThrow();
  });

  it('does not treat shared non-cyclic references as cycles', () => {
    const shared = { v: 1 };
    expect(redactSecrets({ x: shared, y: shared })).toEqual({ x: { v: 1 }, y: { v: 1 } });
  });

  it('never mutates the input and returns a deep clone', () => {
    const key = j('AKIA', 'IOSFODNN7EXAMPLE');
    const input = { password: 'p', nested: { text: key, arr: [key] } };
    const snapshot = structuredClone(input);
    const out = redactSecrets(input);
    expect(input).toEqual(snapshot);
    expect(out).not.toBe(input);
    expect(out.nested).not.toBe(input.nested);
    expect(out.nested.arr).not.toBe(input.nested.arr);
  });

  it('passes primitives through', () => {
    expect(redactSecrets(5)).toBe(5);
    expect(redactSecrets(null)).toBe(null);
    expect(redactSecrets(undefined)).toBe(undefined);
  });
});

describe('redactSecrets: assignments inside text', () => {
  it('redacts AWS secret access keys written as env assignments', () => {
    const s =
      'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
    const out = redactSecrets(s);
    expect(out).not.toContain('wJalrXUtnFEMI');
    expect(out).toContain('AWS_SECRET_ACCESS_KEY=[REDACTED:aws-secret-key]');
    expect(out).toContain('[REDACTED:aws-access-key]');
  });

  it('redacts password/token/api_key assignments and keeps the name', () => {
    expect(redactSecrets('db password: hunter2hunter2')).toBe('db password: [REDACTED:password]');
    expect(redactSecrets('{"api_key": "abcd1234efgh5678"}')).toBe('{"api_key": "[REDACTED:api-key]"}');
    expect(redactSecrets('GITLAB_TOKEN=glpat-xxxxxxxxxxxx')).toBe('GITLAB_TOKEN=[REDACTED:token]');
  });

  it('leaves short values and prose alone', () => {
    expect(redactSecrets('token: abc')).toBe('token: abc');
    expect(redactSecrets('Enter your password to continue.')).toBe('Enter your password to continue.');
  });

  it('does not redact max_tokens style counters by key name', () => {
    expect(redactSecrets({ max_tokens: '100', token: 'abcdef' })).toEqual({
      max_tokens: '100',
      token: '[REDACTED:token]',
    });
  });
});
