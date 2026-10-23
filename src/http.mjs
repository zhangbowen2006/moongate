// HTTP transport for the gateway.
//
// MCP clients speak stdio or Streamable HTTP. This module serves the same
// engine over HTTP: a POST carries one JSON-RPC message, the engine decides,
// and the response is either a direct policy answer or the upstream reply
// matched by JSON-RPC id. GET opens an SSE stream for server-initiated
// messages. The policy code is unchanged — only the pipe is different.
import { spawn } from 'node:child_process';
import { appendFileSync, mkdirSync, writeFileSync } from 'node:fs';
import { createInterface } from 'node:readline';
import { dirname } from 'node:path';
import { createServer } from 'node:http';

const MAX_BODY_BYTES = 8 * 1024 * 1024;

function readBody(req, res) {
  return new Promise((resolve) => {
    let size = 0;
    const chunks = [];
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        res.writeHead(413, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32600, message: 'body exceeds 8 MiB' } }));
        req.destroy();
        resolve(null);
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', () => resolve(null));
  });
}

export async function runHttpGateway(options) {
  const {
    engine,
    policyText,
    command,
    args = [],
    ledgerPath,
    sessionId,
    port = 8787,
    host = '127.0.0.1',
    cwd = process.cwd(),
  } = options;

  const created = JSON.parse(engine.create(policyText, sessionId, BigInt(Date.now())));
  if (!created.ok) {
    throw new Error(`policy rejected: ${created.error}`);
  }
  const handle = created.handle;
  const policy = created.policy;

  mkdirSync(dirname(ledgerPath), { recursive: true });
  writeFileSync(ledgerPath, '', 'utf8');
  const ledgerLines = [];
  const writeLedger = (line) => {
    ledgerLines.push(line);
    appendFileSync(ledgerPath, `${line}\n`, 'utf8');
  };
  for (const action of created.ledger) {
    writeLedger(action.line);
  }

  const child = spawn(command, args, {
    cwd,
    stdio: ['pipe', 'pipe', 'inherit'],
    windowsHide: true,
    env: { ...process.env, MOONGATE: '1' },
  });

  // jsonrpc id -> resolver waiting for the upstream reply.
  const pending = new Map();
  // Open SSE streams for server-initiated messages.
  const sseClients = new Set();

  const dispatchClient = (line) => {
    let parsed;
    try {
      parsed = JSON.parse(line);
    } catch {
      return;
    }
    const key = parsed && parsed.id !== undefined && parsed.id !== null ? String(parsed.id) : null;
    if (key && pending.has(key)) {
      const resolve = pending.get(key);
      pending.delete(key);
      resolve(line);
      return;
    }
    for (const res of sseClients) {
      res.write(`event: message\ndata: ${line}\n\n`);
    }
  };

  const apply = (actions) => {
    for (const action of actions) {
      switch (action.kind) {
        case 'ledger':
          writeLedger(action.line);
          break;
        case 'upstream':
          if (child.stdin.writable) {
            child.stdin.write(`${action.line}\n`);
          } else {
            console.error('[moongate] upstream stdin is closed; dropping a call');
          }
          break;
        case 'client':
          dispatchClient(action.line);
          break;
        case 'approval':
          console.error(`[moongate] approval required: ${action.tool} (${action.call}) rule=${action.rule}`);
          break;
        case 'notice':
          console.error(`[moongate] ${action.message}`);
          break;
        default:
          console.error(`[moongate] unknown action kind: ${action.kind}`);
      }
    }
  };

  const onClientLine = (line) => {
    apply(JSON.parse(engine.client_line(handle, line, BigInt(Date.now()))));
  };
  const onServerLine = (line) => {
    apply(JSON.parse(engine.server_line(handle, line, BigInt(Date.now()))));
  };

  const serverReader = createInterface({ input: child.stdout, crlfDelay: Infinity });
  serverReader.on('line', onServerLine);

  const tick = setInterval(() => {
    try {
      apply(JSON.parse(engine.tick(handle, BigInt(Date.now()))));
    } catch (error) {
      console.error(`[moongate] tick failed: ${error.message}`);
    }
  }, 250);

  const server = createServer(async (req, res) => {
    res.setHeader('access-control-allow-origin', '*');
    res.setHeader('access-control-allow-headers', 'content-type, mcp-session-id, mcp-protocol-version');
    res.setHeader('access-control-expose-headers', 'mcp-session-id');
    if (req.method === 'OPTIONS') {
      res.writeHead(204);
      res.end();
      return;
    }

    const url = (req.url || '').split('?')[0];
    if (url !== '/mcp' && url !== '/mcp/') {
      res.writeHead(404, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ error: 'not found; the endpoint is /mcp' }));
      return;
    }

    if (req.method === 'POST') {
      const body = await readBody(req, res);
      if (body === null) return;
      let msg;
      try {
        msg = JSON.parse(body);
      } catch {
        res.writeHead(400, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'parse error' } }));
        return;
      }
      const hasId = msg && msg.id !== undefined && msg.id !== null;
      let actions;
      try {
        actions = JSON.parse(engine.client_line(handle, body, BigInt(Date.now())));
      } catch (error) {
        res.writeHead(500, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32603, message: `engine failure: ${error.message}` } }));
        return;
      }

      // A decision the engine made itself (deny, protocol error, unsupported
      // method) is answered without touching the upstream.
      const direct = actions.find((a) => a.kind === 'client');
      if (direct) {
        for (const action of actions) {
          if (action.kind === 'ledger') writeLedger(action.line);
          if (action.kind === 'notice') console.error(`[moongate] ${action.message}`);
          if (action.kind === 'upstream' && child.stdin.writable) child.stdin.write(`${action.line}\n`);
        }
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(direct.line);
        return;
      }

      if (!hasId) {
        apply(actions);
        res.writeHead(202);
        res.end();
        return;
      }

      const key = String(msg.id);
      const responseLine = await new Promise((resolve) => {
        pending.set(key, resolve);
        apply(actions);
      });
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(responseLine);
      return;
    }

    if (req.method === 'GET') {
      res.writeHead(200, {
        'content-type': 'text/event-stream',
        'cache-control': 'no-cache',
        connection: 'keep-alive',
      });
      res.write(': connected\n\n');
      sseClients.add(res);
      req.on('close', () => sseClients.delete(res));
      return;
    }

    if (req.method === 'DELETE') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ ok: true }));
      return;
    }

    res.writeHead(405, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ error: 'method not allowed' }));
  });

  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, host, resolve);
  });
  const address = server.address();

  const close = () => {
    clearInterval(tick);
    for (const res of sseClients) res.end();
    sseClients.clear();
    server.close();
    child.kill();
  };

  return {
    ready: {
      session: sessionId,
      policy: policy.name,
      digest: policy.digest,
      ledger: ledgerPath,
      transport: 'http',
      url: `http://${host}:${address.port}/mcp`,
      upstream: [command, ...args].join(' '),
      pid: process.pid,
    },
    server,
    close,
    onClientLine,
  };
}
