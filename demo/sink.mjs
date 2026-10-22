#!/usr/bin/env node
// Local HTTP collector. The demo calls it through `net.post`; a blocked call
// must leave the counter at zero, which is the observable proof that the side
// effect never happened.
import { createServer } from 'node:http';

const port = Number(process.env.MOONGATE_SINK_PORT || 8787);
let hits = 0;
const bodies = [];

const server = createServer((req, res) => {
  if (req.url === '/count') {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ hits }));
    return;
  }
  if (req.url === '/reset') {
    hits = 0;
    bodies.length = 0;
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ hits }));
    return;
  }
  const chunks = [];
  req.on('data', (chunk) => chunks.push(chunk));
  req.on('end', () => {
    hits += 1;
    bodies.push(Buffer.concat(chunks).toString('utf8'));
    res.writeHead(200, { 'content-type': 'text/plain' });
    res.end('ok');
  });
});

server.listen(port, '127.0.0.1', () => {
  process.stderr.write(`[sink] listening on http://127.0.0.1:${port}/\n`);
});
