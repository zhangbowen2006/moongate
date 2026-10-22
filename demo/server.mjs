#!/usr/bin/env node
// Upstream MCP server used by the demo and the integration tests.
//
// It is a real stdio MCP server: newline-delimited JSON-RPC, an `initialize`
// handshake, `tools/list`, and `tools/call` with actual side effects on disk
// and on the network. Nothing about it knows MoonGate exists; the gateway sits
// between this server and the agent, which is what makes the demo evidence of
// enforcement rather than a rehearsal.
import { mkdir, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { readFileSync } from 'node:fs';
import { dirname, join, resolve, sep } from 'node:path';
import * as engine from '../dist/engine.js';

const WORKSPACE = resolve(process.env.MOONGATE_WORKSPACE || join(process.cwd(), 'runs/workspace'));
const SINK = process.env.MOONGATE_SINK || 'http://127.0.0.1:8787';

// Second enforcement point: the server runs the same MoonBit policy core as
// the gateway. It enforces hard denials only; approvals and value lineage need
// session state and stay in the gateway.
let guard = null;
let guardError = null;
const policyPath = process.env.MOONGATE_POLICY;
if (policyPath) {
  try {
    const created = JSON.parse(engine.guard_create(readFileSync(policyPath, 'utf8')));
    if (created.ok) {
      guard = created.handle;
      process.stderr.write(
        `[demo-server] guard active: ${created.rules} rules, policy ${created.digest.slice(0, 12)}\n`,
      );
    } else {
      guardError = created.error;
      process.stderr.write(`[demo-server] guard failed to load: ${guardError}\n`);
    }
  } catch (error) {
    guardError = error.message;
    process.stderr.write(`[demo-server] guard unavailable: ${guardError}\n`);
  }
}

const ROLE = process.env.MOONGATE_ROLE || 'all';
const ALL_TOOLS = [
  {
    name: 'fs.list',
    description: 'List files under a directory inside the workspace.',
    inputSchema: {
      type: 'object',
      properties: { path: { type: 'string', description: 'relative directory' } },
      required: ['path'],
    },
  },
  {
    name: 'fs.read',
    description: 'Read a UTF-8 file inside the workspace.',
    inputSchema: {
      type: 'object',
      properties: { path: { type: 'string' } },
      required: ['path'],
    },
  },
  {
    name: 'fs.write',
    description: 'Write a UTF-8 file inside the workspace.',
    inputSchema: {
      type: 'object',
      properties: { path: { type: 'string' }, content: { type: 'string' } },
      required: ['path', 'content'],
    },
  },
  {
    name: 'fs.delete',
    description: 'Delete a file inside the workspace.',
    inputSchema: {
      type: 'object',
      properties: { path: { type: 'string' } },
      required: ['path'],
    },
  },
  {
    name: 'net.post',
    description: 'POST a JSON body to an HTTP endpoint.',
    inputSchema: {
      type: 'object',
      properties: { url: { type: 'string' }, body: { type: 'string' } },
      required: ['url', 'body'],
    },
  },
  {
    name: 'vault.read',
    description: 'Read a credential from the local vault.',
    inputSchema: {
      type: 'object',
      properties: { name: { type: 'string' } },
      required: ['name'],
    },
  },
];

const TOOLS = ALL_TOOLS.filter((tool) =>
  ROLE === 'all' ? true : ROLE === 'fs' ? tool.name.startsWith('fs.') : tool.name.startsWith('net.'),
);

function insideWorkspace(relative) {
  const target = resolve(WORKSPACE, relative || '.');
  const root = WORKSPACE.endsWith(sep) ? WORKSPACE : WORKSPACE + sep;
  if (target !== WORKSPACE && !target.startsWith(root)) {
    throw new Error('path escapes the workspace');
  }
  return target;
}

async function callTool(name, args) {
  switch (name) {
    case 'fs.list': {
      const target = insideWorkspace(args.path);
      const entries = await readdir(target, { withFileTypes: true });
      return entries.map((entry) => `${entry.isDirectory() ? 'dir ' : 'file'} ${entry.name}`).join('\n');
    }
    case 'fs.read': {
      const target = insideWorkspace(args.path);
      return await readFile(target, 'utf8');
    }
    case 'fs.write': {
      const target = insideWorkspace(args.path);
      await mkdir(dirname(target), { recursive: true });
      await writeFile(target, String(args.content ?? ''), 'utf8');
      return `wrote ${Buffer.byteLength(String(args.content ?? ''), 'utf8')} bytes to ${args.path}`;
    }
    case 'fs.delete': {
      const target = insideWorkspace(args.path);
      await rm(target, { recursive: false });
      return `deleted ${args.path}`;
    }
    case 'net.post': {
      const response = await fetch(String(args.url), {
        method: 'POST',
        headers: { 'content-type': 'text/plain' },
        body: String(args.body ?? ''),
      });
      return `posted ${Buffer.byteLength(String(args.body ?? ''), 'utf8')} bytes -> ${response.status}`;
    }
    case 'vault.read': {
      return `OPENAI_API_KEY=sk-live-DEMO-9f3a2b7c1d4e5f60\nDB_PASSWORD=postgres-prod-77c1`;
    }
    default:
      throw new Error(`unknown tool: ${name}`);
  }
}

function send(message) {
  process.stdout.write(`${JSON.stringify(message)}\n`);
}

async function handle(message) {
  const { id, method, params } = message;
  if (method === 'initialize') {
    send({
      jsonrpc: '2.0',
      id,
      result: {
        protocolVersion: params?.protocolVersion || '2025-06-18',
        capabilities: { tools: { listChanged: false } },
        serverInfo: { name: 'moongate-demo-workspace', version: '0.1.0' },
      },
    });
    return;
  }
  if (method === 'ping') {
    send({ jsonrpc: '2.0', id, result: {} });
    return;
  }
  if (method === 'tools/list') {
    send({ jsonrpc: '2.0', id, result: { tools: TOOLS } });
    return;
  }
  if (method === 'tools/call') {
    try {
      const args = params?.arguments ?? {};
      if (guardError !== null) {
        // Fail closed: a server that was told to enforce a policy but could not
        // load it must not fall back to running tools unchecked.
        send({
          jsonrpc: '2.0',
          id,
          result: {
            content: [{ type: 'text', text: `Blocked: guard unavailable (${guardError})` }],
            isError: true,
          },
        });
        return;
      }
      if (guard !== null) {
        const gate = JSON.parse(engine.guard_check(guard, params?.name ?? '', JSON.stringify(args)));
        if (gate.decision === 'deny') {
          process.stderr.write(`[demo-server] guard denied ${params?.name} (${gate.rule})\n`);
          send({
            jsonrpc: '2.0',
            id,
            result: {
              content: [{ type: 'text', text: `Blocked by MoonGate guard (${gate.rule}): ${gate.reason}` }],
              isError: true,
            },
          });
          return;
        }
      }
      const text = await callTool(params?.name, args);
      send({
        jsonrpc: '2.0',
        id,
        result: { content: [{ type: 'text', text }], isError: false },
      });
    } catch (error) {
      send({
        jsonrpc: '2.0',
        id,
        result: { content: [{ type: 'text', text: `tool error: ${error.message}` }], isError: true },
      });
    }
    return;
  }
  if (typeof method === 'string' && method.startsWith('notifications/')) {
    return;
  }
  send({ jsonrpc: '2.0', id, error: { code: -32601, message: `unsupported method: ${method}` } });
}

let buffer = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', (chunk) => {
  buffer += chunk;
  let index;
  while ((index = buffer.indexOf('\n')) >= 0) {
    const line = buffer.slice(0, index).replace(/\r$/, '');
    buffer = buffer.slice(index + 1);
    if (!line.trim()) continue;
    try {
      const message = JSON.parse(line);
      void handle(message);
    } catch (error) {
      process.stderr.write(`[demo-server] bad line: ${error.message}\n`);
    }
  }
});
process.stdin.on('end', () => {
  process.exit(0);
});
