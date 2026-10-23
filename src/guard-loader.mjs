// MoonGate zero-touch guard loader.
//
// Started with `node --import <this file> <server entry>`, it runs BEFORE the
// MCP server module. It patches `Server.prototype.setRequestHandler` so that
// every `tools/call` is judged by the MoonBit policy engine before the
// server's own handler runs. The server keeps its source untouched: no import,
// no SDK change, no wrapper class.
//
// The SDK is resolved from the server's working directory, not from this file,
// so the patch lands on the exact module instance the server will use.
import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const engineUrl = new URL('../dist/engine.js', import.meta.url);
const engine = await import(engineUrl.href);

function loadPolicy() {
  const fromEnv = process.env.MOONGATE_POLICY_JSON;
  const fromFile = process.env.MOONGATE_POLICY;
  if (fromEnv) return fromEnv;
  if (fromFile) return readFileSync(resolve(fromFile), 'utf8');
  return null;
}

const policyJson = loadPolicy();
if (!policyJson) {
  console.error('[moongate] MOONGATE_POLICY or MOONGATE_POLICY_JSON is required');
  process.exit(2);
}

const created = JSON.parse(engine.guard_create(policyJson));
if (!created.ok) {
  console.error('[moongate] policy rejected:', created.error ?? created);
  process.exit(2);
}
const handle = created.handle;

function judge(tool, args) {
  const verdict = JSON.parse(engine.guard_check(handle, tool, JSON.stringify(args ?? {})));
  return verdict;
}

function resolveFromCwd(specifier) {
  const require = createRequire(resolve(process.cwd(), 'noop.js'));
  const cjs = require.resolve(specifier);
  // The SDK ships dual builds and its `exports` map resolves `require` to
  // dist/cjs. The server is ESM, so patch the dist/esm instance or the patch
  // lands on a class the server never uses.
  const esm = cjs.replace(/dist[\\/]cjs[\\/]/, 'dist/esm/');
  return pathToFileURL(esm).href;
}

const serverUrl = resolveFromCwd('@modelcontextprotocol/sdk/server/index.js');
const typesUrl = resolveFromCwd('@modelcontextprotocol/sdk/types.js');
const { Server } = await import(serverUrl);
const { McpError, ErrorCode } = await import(typesUrl);

const original = Server.prototype.setRequestHandler;
Server.prototype.setRequestHandler = function (schema, handler) {
  const kind = schema?._def?.typeName ?? schema?._def?.shape?.method?.value;
  if (kind !== 'tools/call') {
    return original.call(this, schema, handler);
  }
  const guarded = async (request, extra) => {
    const tool = request?.params?.name ?? '';
    const args = request?.params?.arguments ?? {};
    const verdict = judge(tool, args);
    if (verdict.decision === 'deny') {
      const detail = verdict.reason || verdict.rule || 'denied by policy';
      console.error(`[moongate] blocked ${tool}: ${detail}`);
      throw new McpError(
        ErrorCode.InvalidRequest,
        `Blocked by MoonGate policy (${verdict.rule}): ${detail}`,
      );
    }
    return handler(request, extra);
  };
  return original.call(this, schema, guarded);
};

console.error(`[moongate] zero-touch guard active: ${created.rules} rule(s), digest ${created.digest?.slice(0, 12)}`);
