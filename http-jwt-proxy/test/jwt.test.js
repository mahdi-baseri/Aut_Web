const test = require('node:test');
const assert = require('node:assert/strict');
const { createToken, verifyToken } = require('../jwt');

const secret = 'test-secret-that-has-at-least-32-characters';
const now = Math.floor(Date.now() / 1000);

test('valid JWT works', () => {
  const token = createToken({ sub: 'ali', exp: now + 3600 }, secret);
  assert.equal(verifyToken(token, secret), true);
});

test('expired JWT is rejected', () => {
  const token = createToken({ sub: 'ali', exp: now - 10 }, secret);
  assert.equal(verifyToken(token, secret), false);
});

test('wrong secret is rejected', () => {
  const token = createToken({ sub: 'ali', exp: now + 3600 }, secret);
  assert.equal(verifyToken(token, 'another-long-secret-with-enough-length'), false);
});

test('changed token is rejected', () => {
  const token = createToken({ sub: 'ali', exp: now + 3600 }, secret);
  const parts = token.split('.');
  parts[1] = Buffer.from(JSON.stringify({ sub: 'admin', exp: now + 3600 })).toString('base64url');
  assert.equal(verifyToken(parts.join('.'), secret), false);
});

test('malformed token is rejected', () => {
  assert.equal(verifyToken('not-a-jwt', secret), false);
});
