const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { createProxyServer } = require('../proxy');
const { createToken } = require('../jwt');

const secret = 'test-secret-that-has-at-least-32-characters';

function listen(server) {
  return new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
}

function close(server) {
  return new Promise(resolve => server.close(resolve));
}

test('proxy only forwards requests with valid JWT', async () => {
  const legacy = http.createServer((req, res) => {
    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', () => {
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({
        method: req.method,
        path: req.url,
        body,
        authorization: req.headers.authorization || null
      }));
    });
  });

  await listen(legacy);
  const proxy = createProxyServer(secret, '127.0.0.1', legacy.address().port);
  await listen(proxy);
  const baseUrl = `http://127.0.0.1:${proxy.address().port}`;

  try {
    const noToken = await fetch(`${baseUrl}/get`);
    assert.equal(noToken.status, 401);

    const wrongToken = await fetch(`${baseUrl}/get`, {
      headers: { Authorization: 'Bearer invalid.token.value' }
    });
    assert.equal(wrongToken.status, 401);

    const token = createToken({ sub: 'ali', exp: Math.floor(Date.now() / 1000) + 60 }, secret);
    const response = await fetch(`${baseUrl}/get?name=ali`, {
      headers: { Authorization: `Bearer ${token}` }
    });
    assert.equal(response.status, 200);
    const data = await response.json();
    assert.equal(data.path, '/get?name=ali');
    assert.equal(data.authorization, null);

    const postResponse = await fetch(`${baseUrl}/anything`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'text/plain' },
      body: 'hello'
    });
    const postData = await postResponse.json();
    assert.equal(postData.method, 'POST');
    assert.equal(postData.body, 'hello');
  } finally {
    await close(proxy);
    await close(legacy);
  }
});
