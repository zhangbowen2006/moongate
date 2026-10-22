#!/usr/bin/env node
// Upstream MCP server used by the demo and the integration tests.
//
// It is a real stdio MCP server: newline-delimited JSON-RPC, an `initialize`
// handshake, `tools/list`, and `tools/call` with actual side effects on disk
// and on the network. Nothing about it knows Airlock exists; the gateway sits
// between this server and the agent, which is what makes the demo evidence of
// enforcement rather than a rehearsal.
import { mkdir, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { dirname, join, resolve, sep } from 'node:path';

const WORKSPACE = resolve(process.env.AIRLOCK_WORKSPACE || join(process.cwd(), 'runs/workspace'));
const SINK = process.env.AIRLOCK_SINK || 'http://127.0.0.1:8787';

const TOOLS = [
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
        serverInfo: { name: 'airlock-demo-workspace', version: '0.1.0' },
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
      const text = await callTool(params?.name, params?.arguments ?? {});
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
