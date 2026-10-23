// End-to-end check: the official filesystem server, started through the
// zero-touch guard loader, must refuse a denied tool before its handler runs.
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const here = import.meta.dirname;
const root = resolve(here, '..');
const cli = resolve(root, 'bin/moongate.mjs');
const server = resolve(here, 'node_modules/@modelcontextprotocol/server-filesystem/dist/index.js');
const policy = resolve(root, 'examples/policy.filesystem.json');
const dir = process.argv[2] || '/tmp/mgfs';

const transport = new StdioClientTransport({
  command: process.execPath,
  args: [cli, 'serve', '--policy', policy, '--', process.execPath, server, dir],
  env: { ...process.env },
  cwd: here,
  stderr: 'pipe',
});

const client = new Client({ name: 'guard-check', version: '0.0.1' }, { capabilities: {} });
if (transport.stderr) {
  transport.stderr.on('data', (chunk) => process.stderr.write(`[server] ${chunk}`));
}
await client.connect(transport);

const listed = await client.listTools();
console.log('tools exposed:', listed.tools.map((t) => t.name).join(', '));

let allowed = 0;
let blocked = 0;

try {
  const r = await client.callTool({ name: 'list_directory', arguments: { path: dir } });
  console.log('list_directory -> allowed:', !r.isError);
  allowed += 1;
} catch (e) {
  console.log('list_directory -> unexpected error:', e.message);
}

try {
  const r = await client.callTool({
    name: 'write_file',
    arguments: { path: `${dir}/should-not-exist.txt`, content: 'x' },
  });
  console.log('write_file -> NOT BLOCKED, isError =', r.isError);
} catch (e) {
  console.log('write_file -> blocked:', e.message);
  blocked += 1;
}

const { existsSync } = await import('node:fs');
console.log('side effect present:', existsSync(`${dir}/should-not-exist.txt`));
await client.close();
console.log(blocked === 1 ? 'RESULT: guard works' : 'RESULT: guard FAILED');
process.exit(blocked === 1 ? 0 : 1);
