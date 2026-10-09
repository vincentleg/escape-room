import http from 'node:http';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../web/dist');
const types = { 'index.html': 'text/html; charset=utf-8', 'styles.css': 'text/css; charset=utf-8',
  'app.js': 'application/javascript; charset=utf-8', 'favicon.svg': 'image/svg+xml', 'evidence.json': 'application/json; charset=utf-8' };
const server = http.createServer(async (req, res) => {
  const pathname = new URL(req.url, 'http://localhost').pathname;
  const file = pathname === '/' ? 'index.html' : pathname.slice(1);
  if (!Object.hasOwn(types, file)) { res.writeHead(404).end('Not found'); return; }
  try {
    const body = await readFile(path.join(root, file));
    res.writeHead(200, { 'Content-Type': types[file], 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' });
    res.end(body);
  } catch { res.writeHead(503).end('Run npm run build first.'); }
});
server.on('error', () => { console.error('Local preview unavailable: cannot bind 127.0.0.1:3000.'); process.exitCode = 2; });
server.listen(3000, '127.0.0.1', () => console.log('ESCAPE ROOM preview: http://127.0.0.1:3000'));
