// The version is written in three places (moon.mod, package.json, and the
// MoonBit api). They must agree, or `moongate version` contradicts the docs.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { resolve } from 'node:path';
import { projectRoot } from '../src/engine.mjs';

test('moon.mod, package.json and the CLI report one version', () => {
  const pkg = JSON.parse(readFileSync(resolve(projectRoot, 'package.json'), 'utf8'));
  const moonMod = readFileSync(resolve(projectRoot, 'moon.mod'), 'utf8');
  const moonVersion = moonMod.match(/version\s*=\s*"([^"]+)"/)?.[1];
  assert.ok(moonVersion, 'moon.mod should declare a version');
  assert.equal(pkg.version, moonVersion, 'package.json and moon.mod disagree');

  const out = execFileSync(process.execPath, [resolve(projectRoot, 'bin/moongate.mjs'), 'version'], {
    encoding: 'utf8',
  });
  assert.equal(JSON.parse(out).version, pkg.version, 'moongate version does not match package.json');
});
