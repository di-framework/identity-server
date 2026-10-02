import { mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const appDir = fileURLToPath(new URL('.', import.meta.url));
const outfile = join(appDir, 'dist', 'example-app');
const docker = process.argv.includes('--docker');
const target = compileTarget(docker);

mkdirSync(join(appDir, 'dist'), { recursive: true });

const binary = await Bun.build({
  entrypoints: [join(appDir, 'src/main.ts')],
  compile: {
    outfile,
    autoloadDotenv: false,
    autoloadBunfig: false,
    ...(target ? { target } : {}),
  },
});
if (!binary.success) {
  console.error(binary.logs);
  process.exit(1);
}

console.log(`example-app ${outfile}${target ? ` (${target})` : ''}`);

function compileTarget(docker: boolean): 'bun-linux-arm64' | 'bun-linux-x64' | undefined {
  const requested = process.env.IDENTITY_TARGET;
  if (requested === 'bun-linux-arm64' || requested === 'bun-linux-x64') return requested;
  if (requested) {
    console.error('IDENTITY_TARGET must be bun-linux-arm64 or bun-linux-x64');
    process.exit(1);
  }
  if (!docker) return undefined;
  return process.arch === 'arm64' ? 'bun-linux-arm64' : 'bun-linux-x64';
}
