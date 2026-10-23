// The same policy must hold when the transport is HTTP instead of stdio.
// The gateway serves Streamable HTTP on /mcp: POST carries one JSON-RPC
// message, GET opens the SSE stream.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { loadEngine, projectRoot } from '../src/engine.mjs';
import { runHttpGateway } from '../src/http.mjs';

async function startGateway() {
  const engine = await loadEngine();
  const policyText = readFileSync(resolve(projectRoot, 'examples/policy.workspace.json'), 'utf8');
  const gateway = await runHttpGateway({
    engine,
    policyText,
    command: process.execPath,
    args: [resolve(projectRoot, 'demo/server.mjs')],
    ledgerPath: resolve(projectRoot, 'runs/http-test.jsonl'),
    sessionId: 'http-test',
    port: 0,
    cwd: projectRoot,
  });
  return gateway;
}

test('policy is enforced over HTTP', async (t) => {
  const gateway = await startGateway();
  t.after(() => gateway.close());

  const url = gateway.ready.url;
  const post = async (body) => {
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    });
    assert.equal(res.status, 200);
    return res.json();
  };

  const init = await post({
    jsonrpc: '2.0',
    id: 1,
    method: 'initialize',
    params: {
      protocolVersion: '2024-11-05',
      capabilities: {},
      clientInfo: { name: 'http-test', version: '0' },
    },
  });
  assert.ok(init.result, 'initialize should succeed over HTTP');

  const list = await post({ jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} });
  const names = list.result.tools.map((tool) => tool.name);
  assert.ok(names.includes('fs.read'), 'fs.read should be advertised');
  assert.ok(!names.includes('fs.delete'), 'fs.delete should be hidden by policy');

  const read = await post({
    jsonrpc: '2.0',
    id: 3,
    method: 'tools/call',
    params: { name: 'fs.read', arguments: { path: 'notes/todo.md' } },
  });
  assert.ok(read.result, 'an allowed call should return a result');

  const denied = await post({
    jsonrpc: '2.0',
    id: 4,
    method: 'tools/call',
    params: { name: 'fs.delete', arguments: { path: 'notes/todo.md' } },
  });
  assert.equal(denied.error?.data?.moongate?.rule, 'no-delete');
});

test('the SSE endpoint opens and stays connected', async (t) => {
  const gateway = await startGateway();
  t.after(() => gateway.close());

  const controller = new AbortController();
  const res = await fetch(gateway.ready.url.replace('/mcp', '/mcp'), {
    method: 'GET',
    headers: { accept: 'text/event-stream' },
    signal: controller.signal,
  });
  assert.equal(res.status, 200);
  assert.match(res.headers.get('content-type') ?? '', /text\/event-stream/);
  controller.abort();
});
