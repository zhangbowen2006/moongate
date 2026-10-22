// The gateway process.
//
// Responsibilities, in order: spawn the upstream MCP server, pump lines
// between the agent and that server, execute the actions the MoonBit engine
// returns, and keep the ledger on disk. There is intentionally no policy
// logic here — if this file were deleted, the engine would still make every
// decision; it would simply have no pipes to apply them to.
import { spawn } from 'node:child_process';
import { appendFileSync, mkdirSync, writeFileSync } from 'node:fs';
import { createInterface } from 'node:readline';
import { dirname } from 'node:path';
import { startApprovalBroker } from './approval.mjs';

const MAX_LINE_BYTES = 8 * 1024 * 1024;

export async function runGateway(options) {
  const {
    engine,
    policyText,
    command,
    args = [],
    ledgerPath,
    sessionId,
    port = 0,
    ui = true,
    cwd = process.cwd(),
  } = options;

  const created = JSON.parse(engine.create(policyText, sessionId, BigInt(Date.now())));
  if (!created.ok) {
    throw new Error(`policy rejected: ${created.error}`);
  }
  const handle = created.handle;
  const policy = created.policy;

  mkdirSync(dirname(ledgerPath), { recursive: true });
  // One run, one chain: truncate so a repeated command cannot append a second
  // genesis entry to an existing ledger.
  writeFileSync(ledgerPath, '', 'utf8');
  const ledgerLines = [];
  const writeLedger = (line) => {
    ledgerLines.push(line);
    appendFileSync(ledgerPath, `${line}\n`, 'utf8');
  };
  for (const action of created.ledger) {
    writeLedger(action.line);
  }

  const pending = new Map();
  let broker = null;
  let finished = false;
  let exitCode = 0;

  const upstreamCommand = [command, ...args].map((part) => (/\s/.test(part) ? JSON.stringify(part) : part)).join(' ');
  const child = spawn(command, args, {
    cwd,
    stdio: ['pipe', 'pipe', 'inherit'],
    windowsHide: true,
    env: { ...process.env, AIRLOCK: '1' },
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
      upstream: upstreamCommand,
    };
  };

  const decide = (call, approved) => {
    if (!pending.has(call)) {
      return { ok: false, error: `unknown or already resolved approval: ${call}` };
    }
    const actions = JSON.parse(engine.resolve_approval(handle, call, approved, BigInt(Date.now())));
    apply(actions);
    return { ok: true, call, approved };
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
            console.error('[airlock] upstream stdin is closed; dropping a call');
          }
          break;
        case 'client':
          process.stdout.write(`${action.line}\n`);
          break;
        case 'approval':
          pending.set(action.call, action);
          console.error(
            `[airlock] approval required: ${action.tool} (${action.call}) rule=${action.rule}` +
              (broker ? ` -> ${broker.url}` : ''),
          );
          break;
        case 'approval_resolved':
          pending.delete(action.call);
          break;
        case 'notice':
          console.error(`[airlock] ${action.message}`);
          break;
        default:
          console.error(`[airlock] unknown action kind: ${action.kind}`);
      }
    }
  };

  if (ui) {
    try {
      broker = await startApprovalBroker({ getState: state, decide, port });
    } catch (error) {
      console.error(`[airlock] approval UI unavailable: ${error.message}`);
    }
  }

  const tick = setInterval(() => {
    try {
      apply(JSON.parse(engine.tick(handle, BigInt(Date.now()))));
    } catch (error) {
      console.error(`[airlock] tick failed: ${error.message}`);
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
      console.error(`[airlock] could not write the closing ledger entry: ${error.message}`);
    }
    exitCode = code;
    const shutdown = broker ? broker.close() : Promise.resolve();
    shutdown.finally(() => {
      console.error(`[airlock] stopped; ledger=${ledgerPath}`);
      // Flush stdout before exiting: it carries protocol responses, and
      // process.exit() would otherwise drop buffered writes on Windows.
      process.stdout.write('', () => process.exit(exitCode));
    });
  };

  const onClientLine = (line) => {
    if (Buffer.byteLength(line, 'utf8') > MAX_LINE_BYTES) {
      const error = {
        jsonrpc: '2.0',
        id: null,
        error: { code: -32600, message: 'Airlock: message exceeds the 8 MiB line limit' },
      };
      process.stdout.write(`${JSON.stringify(error)}\n`);
      return;
    }
    try {
      apply(JSON.parse(engine.client_line(handle, line, BigInt(Date.now()))));
    } catch (error) {
      console.error(`[airlock] engine failure on a client line: ${error.message}`);
      finish(3);
    }
  };

  const onServerLine = (line) => {
    try {
      apply(JSON.parse(engine.server_line(handle, line, BigInt(Date.now()))));
    } catch (error) {
      console.error(`[airlock] engine failure on an upstream line: ${error.message}`);
      finish(3);
    }
  };

  const clientReader = createInterface({ input: process.stdin, crlfDelay: Infinity });
  clientReader.on('line', onClientLine);
  clientReader.on('close', () => {
    if (child.stdin.writable) child.stdin.end();
  });

  const serverReader = createInterface({ input: child.stdout, crlfDelay: Infinity });
  serverReader.on('line', onServerLine);

  child.on('error', (error) => {
    console.error(`[airlock] cannot start upstream ${upstreamCommand}: ${error.message}`);
    finish(2);
  });
  let upstreamExit = null;
  child.on('exit', (code, signal) => {
    upstreamExit = { code, signal };
  });
  // Wait for the reader to drain buffered output; a fast upstream can exit
  // before its last response has been processed.
  serverReader.on('close', () => {
    if (upstreamExit && upstreamExit.signal) {
      console.error(`[airlock] upstream terminated by ${upstreamExit.signal}`);
    }
    finish(upstreamExit && upstreamExit.code === 0 ? 0 : 1);
  });

  process.on('SIGINT', () => {
    child.kill();
    finish(130);
  });
  process.on('SIGTERM', () => {
    child.kill();
    finish(143);
  });

  const ready = {
    session: sessionId,
    policy: policy.name,
    digest: policy.digest,
    ledger: ledgerPath,
    approval_url: broker ? broker.url : null,
    upstream: upstreamCommand,
    pid: process.pid,
  };
  console.error(`[airlock] ready ${JSON.stringify(ready)}`);
  return { ready, state, decide, finish, child };
}
