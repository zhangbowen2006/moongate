// Build the MoonBit engine for JavaScript and copy the artifact into dist/.
// The copied file is what `bin/airlock.mjs` imports, so a fresh clone needs
// either `npm run build` (with the MoonBit toolchain installed) or a release
// archive that already contains dist/engine.js.
import { spawnSync } from 'node:child_process';
import { copyFileSync, mkdirSync, existsSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const moon = process.platform === 'win32' ? 'moon.exe' : 'moon';

const build = spawnSync(moon, ['build', 'api', '--target', 'js', '--release', '--deny-warn'], {
  cwd: root,
  stdio: 'inherit',
  env: process.env,
});

if (build.error || build.status !== 0) {
  console.error(
    '[airlock] MoonBit build failed. Install the MoonBit toolchain 0.10.16 or newer and make `moon` available on PATH.',
  );
  process.exit(2);
}

const source = resolve(root, '_build/js/release/build/api/api.js');
if (!existsSync(source)) {
  console.error(`[airlock] expected build artifact at ${source}`);
  process.exit(2);
}

mkdirSync(resolve(root, 'dist'), { recursive: true });
copyFileSync(source, resolve(root, 'dist/engine.js'));
copyFileSync(resolve(root, 'LICENSE'), resolve(root, 'dist/LICENSE'));
copyFileSync(resolve(root, 'third_party/MoonBit-core-LICENSE.txt'), resolve(root, 'dist/MoonBit-core-LICENSE.txt'));
copyFileSync(resolve(root, 'third_party/MoonBit-core-NOTICE.txt'), resolve(root, 'dist/MoonBit-core-NOTICE.txt'));
console.log('[airlock] built dist/engine.js from MoonBit sources');
