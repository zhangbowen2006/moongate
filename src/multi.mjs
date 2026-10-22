// Multi-upstream gateway.
//
// One MCP client, several MCP servers, one policy session. The host merges
// `tools/list`, routes `tools/call` to the server that owns the tool, and feeds
// every response back through the same MoonBit engine. Data lineage therefore
// crosses process boundaries: a secret read from the filesystem server is still
// recognised when an HTTP server is asked to send it.
//
// This file is transport and fan-out only. Every allow/deny/approval/reveal
// decision still comes from the engine.
import { spawn } from 'node:child_process';
import { appendFileSync, mkdirSync, writeFileSync } from 'node:fs';
import { createInterface } from 'node:readline';
import { dirname } from 'node:path';
import { startApprovalBroker } from './approval.mjs';

const MAX_LINE_BYTES = 8 * 1024 * 1024;
const HOST_ID_PREFIX = '__mg_host_';

export async function runMultiGateway(options) {
  const {
    engine,
    policyText,
    servers,
    ledgerPath,
    sessionId,
    port = 0,
    ui = true,
    cwd = process.cwd(),
  } = options;

  const created = JSON.parse(engine.create(policyText, sessionId, BigInt(Date.now())));
  if (!created.ok) throw new Error(`policy rejected: ${created.error}`);
  const handle = created.handle;
  const policy = created.policy;

  mkdirSync(dirname(ledgerPath), { recursive: true });
  writeFileSync(ledgerPath, '', 'utf8');
  const ledgerLines = [];
  const writeLedger = (line) => {
    ledgerLines.push(line);
    appendFileSync(ledgerPath, `${line}\n`, 'utf8');
  };
  for (const action of created.ledger) writeLedger(action.line);

  const entries = servers.map((server) => {
    const child = spawn(server.command, server.args || [], {
      cwd,
      stdio: ['pipe', 'pipe', 'inherit'],
      windowsHide: true,
      env: { ...process.env, ...(server.env || {}), MOONGATE: '1' },
    });
    return {
      name: server.name,
      child,
      pending: new Map(),
      requestSeq: 0,
    };
  });
  const byName = new Map(entries.map((entry) => [entry.name, entry]));
  const toolOwner = new Map();
  const pending = new Map();
  let broker = null;
  let finished = false;
  let hostSeq = 0;

  const sendToClient = (line) => process.stdout.write(`${line}\n`);

  const hostRequest = (entry, method, params, timeoutMs = 8000) =>
    new Promise((resolve, reject) => {
      hostSeq += 1;
      const id = `${HOST_ID_PREFIX}${hostSeq}`;
      const timer = setTimeout(() => {
        entry.pending.delete(id);
        reject(new Error(`${entry.name}: timeout waiting for ${method}`));
      }, timeoutMs);
      entry.pending.set(id, {
        resolve: (value) => {
          clearTimeout(timer);
          resolve(value);
        },
        reject: (error) => {
          clearTimeout(timer);
          reject(error);
        },
      });
      entry.child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id, method, params })}\n`);
    });

  const state = () => {
    const report = JSON.parse(engine.report(JSON.stringify(ledgerLines)));
    return {
      session: sessionId,
      policy: { name: policy.name, digest: policy.digest, rules: policy.rule_count },
      pending: [...pending.values()],
      counts: {
        allowed: report.decisions.allow,
        denied: report.decisions.deny,
        approvals: report.decisions.approval_required,
        tainted: report.results.new_sensitive_values,
      },
      ledger: ledgerPath,
      upstream: entries.map((entry) => entry.name).join(', '),
    };
  };

  const decide = (call, approved) => {
    if (!pending.has(call)) {
      return { ok: false, error: `unknown or already resolved approval: ${call}` };
    }
    apply(JSON.parse(engine.resolve_approval(handle, call, approved, BigInt(Date.now()))));
    return { ok: true, call, approved };
  };

  const routeUpstream = (entry, line) => {
    const message = JSON.parse(line);
    if (message?.method === 'tools/call') {
      const requested = message?.params?.name;
      const target = toolOwner.get(requested);
      if (!target) {
        sendToClient(
          JSON.stringify({
            jsonrpc: '2.0',
            id: message.id,
            error: { code: -32601, message: `MoonGate: no server owns tool ${requested}` },
          }),
        );
        return;
      }
      if (target.prefixed) {
        message.params.name = target.original;
      }
      target.entry.child.stdin.write(`${JSON.stringify(message)}\n`);
      return;
    }
    entry.child.stdin.write(`${line}\n`);
  };

  const apply = (actions) => {
    for (const action of actions) {
      switch (action.kind) {
        case 'ledger':
          writeLedger(action.line);
          break;
        case 'upstream': {
          const first = entries[0];
          routeUpstream(first, action.line);
          break;
        }
        case 'client':
          sendToClient(action.line);
          break;
        case 'approval':
          pending.set(action.call, action);
          console.error(
            `[moongate] approval required: ${action.tool} (${action.call}) rule=${action.rule}` +
              (broker ? ` -> ${broker.url}` : ''),
          );
          break;
        case 'approval_resolved':
          pending.delete(action.call);
          break;
        case 'notice':
          console.error(`[moongate] ${action.message}`);
          break;
        default:
          console.error(`[moongate] unknown action kind: ${action.kind}`);
      }
    }
  };

  if (ui) {
    try {
      broker = await startApprovalBroker({ getState: state, decide, port });
    } catch (error) {
      console.error(`[moongate] approval UI unavailable: ${error.message}`);
    }
  }

  const tick = setInterval(() => {
    try {
      apply(JSON.parse(engine.tick(handle, BigInt(Date.now()))));
    } catch (error) {
      console.error(`[moongate] tick failed: ${error.message}`);
    }
  }, 250);

  const finish = (code) => {
    if (finished) return;
    finished = true;
    clearInterval(tick);
    try {
      for (const action of JSON.parse(engine.close(handle, BigInt(Date.now())))) {
        if (action.kind === 'ledger') writeLedger(action.line);
      }
    } catch (error) {
      console.error(`[moongate] could not write the closing ledger entry: ${error.message}`);
    }
    for (const entry of entries) {
      if (!entry.child.killed) entry.child.kill();
    }
    const shutdown = broker ? broker.close() : Promise.resolve();
    shutdown.finally(() => {
      console.error(`[moongate] stopped; ledger=${ledgerPath}`);
      process.stdout.write('', () => process.exit(code));
    });
  };

  const handleChildLine = (entry, line) => {
    let message;
    try {
      message = JSON.parse(line);
    } catch {
      return;
    }
    if (typeof message.id === 'string' && message.id.startsWith(HOST_ID_PREFIX)) {
      const waiter = entry.pending.get(message.id);
      if (waiter) {
        entry.pending.delete(message.id);
        if (message.error) waiter.reject(new Error(message.error.message || 'host request failed'));
        else waiter.resolve(message.result);
      }
      return;
    }
    try {
      apply(JSON.parse(engine.server_line(handle, line, BigInt(Date.now()))));
    } catch (error) {
      console.error(`[moongate] engine failure on ${entry.name}: ${error.message}`);
      finish(3);
    }
  };

  for (const entry of entries) {
    entry.child.on('error', (error) => {
      console.error(`[moongate] cannot start ${entry.name}: ${error.message}`);
      finish(2);
    });
    entry.child.on('exit', (code) => {
      if (!finished) {
        console.error(`[moongate] upstream ${entry.name} exited with code ${code}`);
        finish(code === 0 ? 0 : 1);
      }
    });
    const reader = createInterface({ input: entry.child.stdout, crlfDelay: Infinity });
    reader.on('line', (line) => handleChildLine(entry, line));
  }

  // Initialise every server once, then learn which tools it owns.
  for (const entry of entries) {
    await hostRequest(entry, 'initialize', {
      protocolVersion: '2025-06-18',
      capabilities: { tools: {} },
      clientInfo: { name: 'moongate-host', version: '0.5.0' },
    });
    entry.child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' })}\n`);
  }
  const listed = [];
  for (const entry of entries) {
    try {
      const result = await hostRequest(entry, 'tools/list', {});
      listed.push({ entry, tools: result.tools || [] });
    } catch (error) {
      console.error(`[moongate] ${entry.name} did not answer tools/list: ${error.message}`);
      listed.push({ entry, tools: [] });
    }
  }
  const counts = new Map();
  for (const { tools } of listed) {
    for (const tool of tools) counts.set(tool.name, (counts.get(tool.name) || 0) + 1);
  }
  const mergedTools = [];
  for (const { entry, tools } of listed) {
    for (const tool of tools) {
      const prefixed = (counts.get(tool.name) || 0) > 1;
      const name = prefixed ? `${entry.name}.${tool.name}` : tool.name;
      toolOwner.set(name, { entry, original: tool.name, prefixed });
      mergedTools.push({ ...tool, name });
    }
  }

  const onClientLine = async (line) => {
    if (Buffer.byteLength(line, 'utf8') > MAX_LINE_BYTES) {
      sendToClient(
        JSON.stringify({
          jsonrpc: '2.0',
          id: null,
          error: { code: -32600, message: 'MoonGate: message exceeds the 8 MiB line limit' },
        }),
      );
      return;
    }
    let message;
    try {
      message = JSON.parse(line);
    } catch {
      apply(JSON.parse(engine.client_line(handle, line, BigInt(Date.now()))));
      return;
    }
    if (message.method === 'initialize') {
      sendToClient(
        JSON.stringify({
          jsonrpc: '2.0',
          id: message.id,
          result: {
            protocolVersion: message.params?.protocolVersion || '2025-06-18',
            capabilities: { tools: { listChanged: false } },
            serverInfo: { name: 'moongate', version: '0.5.0', servers: entries.map((e) => e.name) },
          },
        }),
      );
      return;
    }
    if (message.method === 'notifications/initialized') {
      for (const entry of entries) {
        entry.child.stdin.write(`${line}\n`);
      }
      return;
    }
    if (message.method === 'tools/list') {
      // Let the engine record and later filter the list, but answer it from the
      // merged catalogue rather than one upstream.
      apply(JSON.parse(engine.client_line(handle, line, BigInt(Date.now()))).filter((a) => a.kind !== 'upstream'));
      const response = JSON.stringify({
        jsonrpc: '2.0',
        id: message.id,
        result: { tools: mergedTools },
      });
      apply(JSON.parse(engine.server_line(handle, response, BigInt(Date.now()))));
      return;
    }
    apply(JSON.parse(engine.client_line(handle, line, BigInt(Date.now()))));
  };

  let queue = Promise.resolve();
  const clientReader = createInterface({ input: process.stdin, crlfDelay: Infinity });
  clientReader.on('line', (line) => {
    queue = queue
      .then(() => onClientLine(line))
      .catch((error) => {
        console.error(`[moongate] client line failed: ${error.message}`);
      });
  });
  clientReader.on('close', () => {
    for (const entry of entries) {
      if (entry.child.stdin.writable) entry.child.stdin.end();
    }
  });

  process.on('SIGINT', () => finish(130));
  process.on('SIGTERM', () => finish(143));

  const ready = {
    session: sessionId,
    policy: policy.name,
    digest: policy.digest,
    ledger: ledgerPath,
    approval_url: broker ? broker.url : null,
    servers: entries.map((entry) => entry.name),
    tools: mergedTools.map((tool) => tool.name),
    pid: process.pid,
  };
  console.error(`[moongate] ready ${JSON.stringify(ready)}`);
  return { ready, state, decide, finish, entries, byName };
}
