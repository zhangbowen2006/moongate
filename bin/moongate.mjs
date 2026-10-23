#!/usr/bin/env node
// Command line entry point.
//
// `run` starts the in-path gateway; the other commands operate on artifacts a
// run produced (policy check, ledger verification, HTML report). All policy
// reasoning happens in the MoonBit engine; this file is argv handling and
// file I/O.
import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { spawn } from 'node:child_process';
import { dirname, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { loadEngine, projectRoot } from '../src/engine.mjs';
import { runGateway } from '../src/gateway.mjs';
import { runMultiGateway } from '../src/multi.mjs';
import { renderReport } from '../src/report.mjs';

const HELP = `moongate — in-path policy and data-provenance gateway for MCP agents

Usage
  moongate run --policy <file> [--ledger <file>] [--port <n>] [--no-ui] -- <upstream command...>
  moongate serve --policy <file> -- node <server entry> [args...]
  moongate check --policy <file>
  moongate verify --ledger <file> [--json]
  moongate report --ledger <file> [--out <file.html>] [--policy <file>]
  moongate import-policy --format moonpod --in <policy.json> [--out <policy.json>]
  moongate version

Examples
  moongate run --policy examples/policy.workspace.json -- node demo/server.mjs
  moongate run --policy examples/policy.workspace.json -- npx -y @modelcontextprotocol/server-filesystem ./workspace
  moongate serve --policy examples/policy.filesystem.json -- node node_modules/@modelcontextprotocol/server-filesystem/dist/index.js ./workspace

run puts a gateway in front of the server (client must be pointed at it).
serve leaves the client and server untouched: it starts the server with an
in-process guard, so the same policy is enforced inside the server itself.

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
  if (!flags.servers && !rest.length) fail('run requires an upstream command after --');
  if (flags.servers && rest.length) fail('use either --servers or -- <command>, not both');
  const policyPath = resolve(flags.policy || join(projectRoot, 'examples/policy.workspace.json'));
  if (!existsSync(policyPath)) fail(`policy not found: ${policyPath}`);
  const engine = await loadEngine();
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const sessionId = flags.session || `run-${stamp}`;
  const ledgerPath = resolve(flags.ledger || join('runs', `${sessionId}.jsonl`));
  mkdirSync(dirname(ledgerPath), { recursive: true });
  const common = {
    engine,
    policyText: readFileSync(policyPath, 'utf8'),
    ledgerPath,
    sessionId,
    port: flags.port ? Number(flags.port) : 0,
    ui: flags['no-ui'] !== true,
    cwd: process.cwd(),
  };
  if (flags.servers) {
    const config = JSON.parse(readFileSync(resolve(flags.servers), 'utf8'));
    if (!Array.isArray(config.servers) || config.servers.length === 0) {
      fail('--servers file must contain { "servers": [ ... ] }');
    }
    await runMultiGateway({ ...common, servers: config.servers });
  } else {
    await runGateway({ ...common, command: rest[0], args: rest.slice(1) });
  }
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
  console.log(`secrets     mask=${policy.mask_secrets}, reveal rules=${policy.reveal_count}`);
  console.log(`egress      ${policy.egress_tools.join(', ') || '(none)'} -> ${policy.on_taint} on taint`);
  console.log(`rate        ${policy.rate_max_calls} calls / ${policy.rate_window_ms} ms`);
  console.log(
    `budget      calls=${policy.budget.max_calls || '∞'} ` +
      `bytes=${policy.budget.max_arg_bytes || '∞'} ` +
      `single=${policy.budget.max_single_bytes || '∞'} reveals=${policy.budget.max_reveals || '∞'}`,
  );
  console.log(`approval    ttl ${policy.approval_ttl_ms} ms, hide denied tools: ${policy.hide_denied}`);
  console.log('rules in evaluation order:');
  for (const rule of policy.rules) {
    const shape = rule.conditional ? 'conditional' : 'always';
    console.log(`  ${rule.id.padEnd(18)} ${rule.decision.padEnd(9)} ${rule.tool.padEnd(18)} ${shape}`);
  }
  // A cheap but useful lint: an earlier unconditional rule with the same tool
  // pattern makes a later rule unreachable. Catch the obvious case instead of
  // pretending to solve glob subsumption.
  if (policy.default === 'allow') {
    console.warn('warning: default decision is allow; a missing rule will permit the call');
  }
  if (!policy.mask_secrets && policy.sensitive_count > 0) {
    console.warn('warning: mask_secrets is false, sensitive values will reach the model');
  }
  for (const rule of policy.rules) {
    if (rule.decision === 'allow' && (rule.tool === '*' || rule.tool === '**')) {
      console.warn(`warning: rule "${rule.id}" allows every tool`);
    }
  }
  for (const rule of policy.reveal || []) {
    if (!rule.conditional) {
      console.warn(`warning: reveal rule "${rule.id}" applies to every destination`);
    } else if (rule.tool === '*' || rule.tool === '**') {
      console.warn(`warning: reveal rule "${rule.id}" targets every tool`);
    }
  }
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

async function commandImportPolicy(argv) {
  const { flags } = parseFlags(argv);
  if (!flags.in) fail('import-policy requires --in <file>');
  const format = flags.format || 'moonpod';
  const engine = await loadEngine();
  const source = readFileSync(resolve(flags.in), 'utf8');
  const result = JSON.parse(engine.import_policy(source, format));
  if (!result.ok) {
    console.error(`import failed: ${result.error}`);
    process.exit(1);
  }
  const rendered = JSON.stringify(result.policy, null, 2);
  if (flags.out) {
    writeFileSync(resolve(flags.out), `${rendered}\n`, 'utf8');
    console.log(`imported ${format} policy -> ${flags.out}`);
  } else {
    console.log(rendered);
  }
  console.log(`  rules ${result.policy.rules.length}, budget ${JSON.stringify(result.policy.budget)}`);
}

async function commandVersion() {
  const engine = await loadEngine();
  console.log(engine.version());
}

async function commandServe(argv) {
  const { flags, rest } = parseFlags(argv);
  if (!flags.policy) fail('serve requires --policy <file>');
  if (rest.length === 0) fail('serve requires a server command after --');
  const [program, ...args] = rest;
  const base = program.split(/[\\/]/).pop().toLowerCase();
  if (base !== 'node' && base !== 'node.exe') {
    fail('serve wraps servers launched with node; use: moongate serve --policy p.json -- node <entry.js>');
  }
  const loader = pathToFileURL(resolve(projectRoot, 'src/guard-loader.mjs')).href;
  const env = { ...process.env, MOONGATE_POLICY: resolve(flags.policy) };
  const child = spawn(program, ['--import', loader, ...args], { stdio: 'inherit', env });
  child.on('exit', (code, signal) => {
    process.exit(code === null ? (signal ? 1 : 0) : code);
  });
}

const [command, ...rest] = process.argv.slice(2);
try {
  switch (command) {
    case 'run':
      await commandRun(rest);
      break;
    case 'serve':
      await commandServe(rest);
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
    case 'import-policy':
      await commandImportPolicy(rest);
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
