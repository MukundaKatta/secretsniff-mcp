import { strict as assert } from 'node:assert';
import { test } from 'node:test';

import { scanText, shannonEntropy } from '../src/scanner.js';

const opts = {
  minEntropy: 4.5,
  minEntropyLength: 32,
  includeHighEntropy: true,
};

test('aws key detected', () => {
  const f = scanText('aws = AKIAIOSFODNN7EXAMPLE\n', opts);
  assert.ok(f.some((x) => x.kind === 'AWS_ACCESS_KEY'));
});

test('github token detected', () => {
  const t = 'ghp_abcdefghijklmnopqrstuvwxyz0123456789';
  const f = scanText(`token = ${t}\n`, opts);
  assert.ok(f.some((x) => x.kind === 'GITHUB_TOKEN'));
});

test('slack token detected', () => {
  const f = scanText('slack = xoxb-1234567890-abcdef\n', opts);
  assert.ok(f.some((x) => x.kind === 'SLACK_TOKEN'));
});

test('stripe key detected', () => {
  const f = scanText('STRIPE = sk_live_abcdefghij1234567890\n', opts);
  assert.ok(f.some((x) => x.kind === 'STRIPE_KEY'));
});

test('jwt detected', () => {
  const j = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1MSJ9.signature_part_long_enough';
  const f = scanText(`auth = '${j}'`, opts);
  assert.ok(f.some((x) => x.kind === 'JWT'));
});

test('rsa marker detected', () => {
  const f = scanText('-----BEGIN RSA PRIVATE KEY-----\nMII...\n', opts);
  assert.ok(f.some((x) => x.kind === 'RSA_PRIVATE_KEY'));
});

test('ssh marker detected', () => {
  const f = scanText('-----BEGIN OPENSSH PRIVATE KEY-----\n', opts);
  assert.ok(f.some((x) => x.kind === 'SSH_PRIVATE_KEY'));
});

test('generic api_key detected', () => {
  const f = scanText('api_key = "abcdefghijklmnopqrst"', opts);
  assert.ok(f.some((x) => x.kind === 'GENERIC_API_KEY'));
});

test('high-entropy detected', () => {
  const blob = 'K3s9Q2pXq9ZTm4Lp2Vw7Yc1RnFb5Xh6N';
  const f = scanText(`token = '${blob}'`, opts);
  assert.ok(f.some((x) => x.kind === 'HIGH_ENTROPY'));
});

test('low-entropy not flagged', () => {
  const blob = 'a'.repeat(32);
  const f = scanText(`v = '${blob}'`, opts);
  assert.ok(!f.some((x) => x.kind === 'HIGH_ENTROPY'));
});

test('clean source produces no findings', () => {
  const f = scanText('function add(a, b) { return a + b; }\n', opts);
  assert.equal(f.length, 0);
});

test('line/column are correct on multiline', () => {
  const src = 'line1\nline2 AKIAIOSFODNN7EXAMPLE\nline3\n';
  const f = scanText(src, opts);
  assert.equal(f.length, 1);
  assert.equal(f[0].line, 2);
  assert.equal(f[0].column, 7);
});

test('findings sorted by position', () => {
  const src = 'ghp_abcdefghijklmnopqrstuvwxyz0123456789 then AKIAIOSFODNN7EXAMPLE';
  const f = scanText(src, opts);
  assert.ok(f.length >= 2);
  for (let i = 1; i < f.length; i++) {
    assert.ok(f[i - 1].start <= f[i].start);
  }
});

test('high-entropy can be disabled', () => {
  const blob = 'K3s9Q2pXq9ZTm4Lp2Vw7Yc1RnFb5Xh6N';
  const f = scanText(`token = '${blob}'`, { ...opts, includeHighEntropy: false });
  assert.ok(!f.some((x) => x.kind === 'HIGH_ENTROPY'));
});

test('high-entropy does not double up on a known pattern', () => {
  // ghp_ token also passes the high-entropy filter; we should only get
  // GITHUB_TOKEN, not also HIGH_ENTROPY for the same span.
  const t = 'ghp_abcdefghijklmnopqrstuvwxyz0123456789';
  const f = scanText(`t = '${t}'`, opts);
  const tokenStart = `t = '`.length;
  const tokenEnd = tokenStart + t.length;
  const overlapping = f.filter(
    (x) => x.kind === 'HIGH_ENTROPY' && x.start >= tokenStart && x.end <= tokenEnd,
  );
  assert.equal(overlapping.length, 0);
});

test('invalid min_entropy rejected', () => {
  assert.throws(() => scanText('hi', { ...opts, minEntropy: 100 }));
});

test('shannon entropy zero for constant string', () => {
  assert.equal(shannonEntropy('aaaa'), 0);
});

test('shannon entropy ~2 for 4-char alphabet equally distributed', () => {
  // 4 distinct chars, each appearing twice -> 2 bits/char.
  const e = shannonEntropy('abcdabcd');
  assert.ok(Math.abs(e - 2.0) < 1e-6);
});
