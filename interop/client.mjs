#!/usr/bin/env node
// Interop proof.
//
// Both ends are official packages: the client is @modelcontextprotocol/sdk and
// the upstream is @modelcontextprotocol/server-filesystem. Airlock sits
// between them without either side knowing. If the gateway were only a
// simulator, this script would fail at the handshake.
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { existsSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, '..');
const WORKSPACE = join(ROOT, 'runs/interop-workspace');
const LEDGER = join(ROOT, 'runs/interop.jsonl');
const UPSTREAM = join(HERE, 'node_modules/@modelcontextprotocol/server-filesystem/dist/index.js');

if (!existsSync(UPSTREAM)) {
  console.error('run `npm install` inside interop/ first');
  process.exit(2);
}

rmSync(WORKSPACE, { recursive: true, force: true });
mkdirSync(WORKSPACE, { recursive: true });
writeFileSync(join(WORKSPACE, 'note.txt'), 'hello from the filesystem server\n');

const transport = new StdioClientTransport({
  command: process.execPath,
  args: [
    join(ROOT, 'bin/airlock.mjs'),
    'run',
    '--policy',
    join(HERE, 'policy.filesystem.json'),
    '--ledger',
    LEDGER,
    '--no-ui',
    '--',
    process.execPath,
    UPSTREAM,
    WORKSPACE,
  ],
  cwd: ROOT,
  stderr: 'pipe',
});

const client = new Client({ name: 'airlock-interop', version: '0.1.0' });
transport.stderr?.setEncoding('utf8');
transport.stderr?.on('data', (chunk) => {
  const text = String(chunk).trim();
  if (text) console.log(`  · ${text}`);
});

const checks = [];
const check = (label, ok, detail = '') => {
  checks.push(ok);
  console.log(`  ${ok ? '\u2713' : '\u2717'} ${label}${detail ? ` — ${detail}` : ''}`);
};

try {
  await client.connect(transport);
  const server = client.getServerVersion();
  console.log(`Airlock 互操作检查 · 第三方客户端 + 第三方服务端`);
  console.log(`  服务端 ${server?.name} ${server?.version}`);

  const listed = await client.listTools();
  const names = listed.tools.map((tool) => tool.name);
  console.log(`  工具 ${names.length} 个：${names.join(', ')}`);
  // move_file/write_file are denied unconditionally, so they must be hidden.
  check('工具清单经过网关裁剪', !names.includes('write_file') && !names.includes('move_file'));

  const note = await client.callTool({ name: 'read_file', arguments: { path: 'note.txt' } });
  check('第三方工具正常调用', String(note.content?.[0]?.text ?? '').includes('hello'));

  let denied = null;
  try {
    await client.callTool({ name: 'read_file', arguments: { path: '../outside.txt' } });
  } catch (error) {
    denied = error;
  }
  check('越界路径被网关拦下', denied !== null, denied?.message);

  let writeDenied = false;
  try {
    await client.callTool({ name: 'write_file', arguments: { path: 'new.txt', content: 'x' } });
  } catch {
    writeDenied = true;
  }
  check('被禁用的写工具无法执行', writeDenied && !existsSync(join(WORKSPACE, 'new.txt')));
} finally {
  await client.close();
}

const passed = checks.filter(Boolean).length;
console.log(`\n${passed}/${checks.length} 项通过，账本 ${LEDGER}`);
process.exit(passed === checks.length ? 0 : 1);
