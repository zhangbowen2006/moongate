#!/usr/bin/env node
// Command line entry point.
//
// `run` starts the in-path gateway; the other commands operate on artifacts a
// run produced (policy check, ledger verification, HTML report). All policy
// reasoning happens in the MoonBit engine; this file is argv handling and
// file I/O.
import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { loadEngine, projectRoot } from '../src/engine.mjs';
import { runGateway } from '../src/gateway.mjs';
import { renderReport } from '../src/report.mjs';

const HELP = `moongate — in-path policy and data-provenance gateway for MCP agents

Usage
  moongate run --policy <file> [--ledger <file>] [--port <n>] [--no-ui] -- <upstream command...>
  moongate check --policy <file>
  moongate verify --ledger <file> [--json]
  moongate report --ledger <file> [--out <file.html>] [--policy <file>]
  moongate version

Examples
  moongate run --policy examples/policy.workspace.json -- node demo/server.mjs
  moongate run --policy examples/policy.workspace.json -- npx -y @modelcontextprotocol/server-filesystem ./workspace

The gateway speaks MCP over stdio. Point any MCP client at this command instead
of the upstream server; denied calls never reach the server.
`;

function parseFlags(argv) {
  const flags = {};
  const rest = [];
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (token === '--') {
      rest.push(...argv.slice(i + 1));
      break;
    }
    if (token.startsWith('--')) {
      const [key, inline] = token.slice(2).split('=');
      if (inline !== undefined) {
        flags[key] = inline;
      } else if (key === 'no-ui' || key === 'json') {
        flags[key] = true;
      } else {
        flags[key] = argv[i + 1];
        i += 1;
      }
    } else {
      rest.push(token);
    }
  }
  return { flags, rest };
}

function fail(message) {
  console.error(`moongate: ${message}`);
  process.exit(2);
}

function readLedger(path) {
  if (!existsSync(path)) fail(`ledger not found: ${path}`);
  return readFileSync(path, 'utf8')
    .split(/\r?\n/)
    .filter((line) => line.trim().length > 0);
}

async function commandRun(argv) {
  const { flags, rest } = parseFlags(argv);
  if (!rest.length) fail('run requires an upstream command after --');
  const policyPath = resolve(flags.policy || join(projectRoot, 'examples/policy.workspace.json'));
  if (!existsSync(policyPath)) fail(`policy not found: ${policyPath}`);
  const engine = await loadEngine();
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const sessionId = flags.session || `run-${stamp}`;
  const ledgerPath = resolve(flags.ledger || join('runs', `${sessionId}.jsonl`));
  mkdirSync(dirname(ledgerPath), { recursive: true });
  await runGateway({
    engine,
    policyText: readFileSync(policyPath, 'utf8'),
    command: rest[0],
    args: rest.slice(1),
    ledgerPath,
    sessionId,
    port: flags.port ? Number(flags.port) : 0,
    ui: flags['no-ui'] !== true,
    cwd: process.cwd(),
  });
}

async function commandCheck(argv) {
  const { flags } = parseFlags(argv);
  const policyPath = resolve(flags.policy || join(projectRoot, 'examples/policy.workspace.json'));
  if (!existsSync(policyPath)) fail(`policy not found: ${policyPath}`);
  const engine = await loadEngine();
  const result = JSON.parse(engine.inspect(readFileSync(policyPath, 'utf8')));
  if (!result.ok) {
    console.error(`policy rejected: ${result.error}`);
    process.exit(1);
  }
  const policy = result.policy;
  console.log(`policy      ${policy.name}`);
  console.log(`digest      ${policy.digest}`);
  console.log(`default     ${policy.default}`);
  console.log(`rules       ${policy.rule_count} (${policy.rules.length} listed)`);
  console.log(`sensitive   ${policy.sensitive_count} source rule(s)`);
  console.log(`egress      ${policy.egress_tools.join(', ') || '(none)'} -> ${policy.on_taint} on taint`);
  console.log(`rate        ${policy.rate_max_calls} calls / ${policy.rate_window_ms} ms`);
  console.log(`approval    ttl ${policy.approval_ttl_ms} ms, hide denied tools: ${policy.hide_denied}`);
  console.log('rules in evaluation order:');
  for (const rule of policy.rules) {
    const shape = rule.conditional ? 'conditional' : 'always';
    console.log(`  ${rule.id.padEnd(18)} ${rule.decision.padEnd(9)} ${rule.tool.padEnd(18)} ${shape}`);
  }
  // A cheap but useful lint: an earlier unconditional rule with the same tool
  // pattern makes a later rule unreachable. Catch the obvious case instead of
  // pretending to solve glob subsumption.
  const seen = new Map();
  for (const rule of policy.rules) {
    if (rule.conditional) continue;
    if (seen.has(rule.tool)) {
      console.warn(
        `warning: rule "${rule.id}" is unreachable; "${seen.get(rule.tool)}" matches the same tool first`,
      );
    } else {
      seen.set(rule.tool, rule.id);
    }
  }
}

async function commandVerify(argv) {
  const { flags } = parseFlags(argv);
  if (!flags.ledger) fail('verify requires --ledger <file>');
  const engine = await loadEngine();
  const lines = readLedger(resolve(flags.ledger));
  const result = JSON.parse(engine.verify(JSON.stringify(lines)));
  if (flags.json) {
    console.log(JSON.stringify(result, null, 2));
  } else if (result.ok) {
    console.log(`chain intact: ${result.entries} entries, head ${result.head.slice(0, 16)}…`);
  } else {
    console.error(`chain broken: ${result.reason} (after ${result.entries} entries)`);
  }
  process.exit(result.ok ? 0 : 1);
}

async function commandReport(argv) {
  const { flags } = parseFlags(argv);
  if (!flags.ledger) fail('report requires --ledger <file>');
  const ledgerPath = resolve(flags.ledger);
  const engine = await loadEngine();
  const lines = readLedger(ledgerPath);
  const report = JSON.parse(engine.report(JSON.stringify(lines)));
  const verify = JSON.parse(engine.verify(JSON.stringify(lines)));
  const out = resolve(flags.out || ledgerPath.replace(/\.jsonl$/, '') + '.report.html');
  mkdirSync(dirname(out), { recursive: true });
  writeFileSync(
    out,
    renderReport({ report, verify, ledgerPath, policyPath: flags.policy ? resolve(flags.policy) : '' }),
    'utf8',
  );
  console.log(`report: ${out}`);
  console.log(
    `  ${report.decisions.executed} executed (${report.decisions.allow} direct, ` +
      `${report.decisions.executed - report.decisions.allow} after approval), ` +
      `${report.decisions.deny} blocked, ${report.decisions.approval_required} approval requests, ` +
      `chain ${verify.ok ? 'intact' : 'BROKEN'}`,
  );
  process.exit(verify.ok ? 0 : 1);
}

async function commandVersion() {
  const engine = await loadEngine();
  console.log(engine.version());
}

const [command, ...rest] = process.argv.slice(2);
try {
  switch (command) {
    case 'run':
      await commandRun(rest);
      break;
    case 'check':
      await commandCheck(rest);
      break;
    case 'verify':
      await commandVerify(rest);
      break;
    case 'report':
      await commandReport(rest);
      break;
    case 'version':
    case '--version':
      await commandVersion();
      break;
    case undefined:
    case 'help':
    case '--help':
    case '-h':
      console.log(HELP);
      break;
    default:
      fail(`unknown command: ${command} (try: moongate help)`);
  }
} catch (error) {
  console.error(`moongate: ${error.message}`);
  process.exit(2);
}
