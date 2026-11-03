const http = require('node:http');
const { verifyToken } = require('./jwt');

function createProxyServer(secret, upstreamHost, upstreamPort) {
  if (!secret || secret.length < 32) {
    throw new Error('JWT_SECRET must have at least 32 characters.');
  }

  return http.createServer((req, res) => {
    const auth = req.headers.authorization || '';
    const match = auth.match(/^Bearer (\S+)$/);

    if (!match || !verifyToken(match[1], secret)) {
      res.writeHead(401, {
        'Content-Type': 'application/json; charset=utf-8',
        'Cache-Control': 'no-store',
        'WWW-Authenticate': 'Bearer'
      });
      res.end(JSON.stringify({ error: 'Unauthorized' }));
      return;
    }

    const headers = { ...req.headers };
    delete headers.authorization;
    delete headers['proxy-authorization'];
    delete headers['proxy-connection'];
    delete headers.connection;
    delete headers.host;
    delete headers['transfer-encoding'];
    delete headers['x-forwarded-for'];
    delete headers['x-forwarded-proto'];
    delete headers['x-forwarded-host'];
    delete headers.forwarded;

    headers.host = `${upstreamHost}:${upstreamPort}`;
    headers['x-forwarded-for'] = req.socket.remoteAddress || '';
    headers['x-forwarded-proto'] = 'http';

    const upstream = http.request({
      hostname: upstreamHost,
      port: upstreamPort,
      path: req.url,
      method: req.method,
      headers,
      timeout: 10000
    }, upstreamResponse => {
      const responseHeaders = { ...upstreamResponse.headers };
      delete responseHeaders.connection;
      delete responseHeaders['transfer-encoding'];
      res.writeHead(upstreamResponse.statusCode || 502, responseHeaders);
      upstreamResponse.pipe(res);
    });

    upstream.on('timeout', () => upstream.destroy(new Error('Timeout')));
    upstream.on('error', () => {
      if (!res.headersSent) {
        res.writeHead(502, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Bad Gateway' }));
      } else {
        res.destroy();
      }
    });

    req.on('aborted', () => upstream.destroy());
    req.pipe(upstream);
  });
}

if (require.main === module) {
  const server = createProxyServer(
    process.env.JWT_SECRET,
    process.env.UPSTREAM_HOST || 'legacy',
    Number(process.env.UPSTREAM_PORT || 8081)
  );
  server.listen(3000, '0.0.0.0', () => {
    console.log('JWT proxy listening on port 3000');
  });
}

module.exports = { createProxyServer };
