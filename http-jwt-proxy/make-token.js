const { createToken } = require('./jwt');

const secret = process.env.JWT_SECRET;
if (!secret || secret.length < 32) {
  console.error('JWT_SECRET must have at least 32 characters.');
  process.exit(1);
}

const now = Math.floor(Date.now() / 1000);
const payload = {
  sub: 'demo-user',
  iat: now,
  exp: now + 3600
};

console.log(createToken(payload, secret));
