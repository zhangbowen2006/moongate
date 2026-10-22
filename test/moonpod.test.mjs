import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { join, resolve, dirname } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const BIN = join(ROOT, 'bin/moongate.mjs');
const SAMPLE = join(ROOT, 'examples/policy.moonpod.json');

function run(args) {
  return spawnSync(process.execPath, [BIN, ...args], { cwd: ROOT, encoding: 'utf8' });
}

test('imports a MoonPod policy and the result passes policy checks', () => {
  const dir = mkdtempSync(join(tmpdir(), 'moongate-pod-'));
  const out = join(dir, 'policy.json');
  const imported = run(['import-policy', '--format', 'moonpod', '--in', SAMPLE, '--out', out]);
  assert.equal(imported.status, 0, imported.stderr);
  const policy = JSON.parse(readFileSync(out, 'utf8'));
  assert.equal(policy.name, 'imported-moonpod');
  assert.equal(policy.budget.max_calls, 25);
  assert.equal(policy.budget.max_single_bytes, 4096);
  assert.ok(policy.rules.some((rule) => rule.decision === 'deny'));
  const checked = run(['check', '--policy', out]);
  assert.equal(checked.status, 0, checked.stderr);
});

test('unsupported MoonPod fields fail closed', () => {
  const dir = mkdtempSync(join(tmpdir(), 'moongate-pod-'));
  const input = join(dir, 'pod.json');
  writeFileSync(
    input,
    JSON.stringify({
      schema_version: 1,
      allowed_tools: ['fs.read'],
      tool_quotas: [{ tool: 'fs.read', max_calls: 1 }],
    }),
  );
  const result = run(['import-policy', '--format', 'moonpod', '--in', input]);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /tool_quotas/);
});
