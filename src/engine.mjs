// Loads the compiled MoonBit engine. The engine is a plain ESM module with
// functions that take and return JSON strings; keeping the import in one file
// makes it obvious that no policy logic lives on the JavaScript side.
import { existsSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
export const projectRoot = root;

let cached = null;

export async function loadEngine() {
  if (cached) return cached;
  const artifact = resolve(root, 'dist/engine.js');
  if (!existsSync(artifact)) {
    throw new Error(
      'dist/engine.js is missing. Run `npm run build` with MoonBit 0.10.16+ installed, or use a release archive that ships the built engine.',
    );
  }
  cached = await import(pathToFileURL(artifact).href);
  return cached;
}
