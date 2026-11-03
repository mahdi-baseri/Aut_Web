const crypto = require('node:crypto');

function toBase64Url(value) {
  return Buffer.from(JSON.stringify(value)).toString('base64url');
}

function createToken(payload, secret) {
  const header = { alg: 'HS256', typ: 'JWT' };
  const data = `${toBase64Url(header)}.${toBase64Url(payload)}`;
  const signature = crypto
    .createHmac('sha256', secret)
    .update(data)
    .digest('base64url');

  return `${data}.${signature}`;
}

function verifyToken(token, secret) {
  if (typeof token !== 'string' || token.length > 4096) {
    return false;
  }

  const parts = token.split('.');
  if (parts.length !== 3 || parts.some(part => !/^[a-zA-Z0-9_-]+$/.test(part))) {
    return false;
  }

  try {
    const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    const now = Math.floor(Date.now() / 1000);

    if (header.alg !== 'HS256' || header.typ !== 'JWT') return false;
    if (!payload || typeof payload.sub !== 'string' || !payload.sub) return false;
    if (!Number.isSafeInteger(payload.exp) || payload.exp <= now) return false;
    if (payload.nbf !== undefined && (!Number.isSafeInteger(payload.nbf) || payload.nbf > now)) return false;

    const expected = crypto.createHmac('sha256', secret)
      .update(`${parts[0]}.${parts[1]}`)
      .digest();
    const received = Buffer.from(parts[2], 'base64url');

    return received.length === expected.length &&
      crypto.timingSafeEqual(received, expected);
  } catch {
    return false;
  }
}

module.exports = { createToken, verifyToken };
