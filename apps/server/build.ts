import { cpSync, mkdirSync, readdirSync, realpathSync, rmSync, symlinkSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const serverDir = fileURLToPath(new URL('.', import.meta.url));
const repoRoot = fileURLToPath(new URL('../..', import.meta.url));
const stage = join(serverDir, '.compile');
const embedded = join(stage, 'embedded');
const outfile = join(serverDir, 'dist', 'identity-server');
const docker = process.argv.includes('--docker');
const target = compileTarget(docker);

const openapi = join(repoRoot, 'apps/api/api/v1/openapi.yaml');
const indexHtml = join(repoRoot, 'apps/client/index.html');
const migrations = join(repoRoot, 'packages/migrations/migrations');
const clientEntry = join(repoRoot, 'apps/client/src/main.tsx');

rmSync(stage, { recursive: true, force: true });
mkdirSync(join(embedded, 'assets'), { recursive: true });
mkdirSync(join(embedded, 'migrations'), { recursive: true });
mkdirSync(join(serverDir, 'dist'), { recursive: true });

cpSync(openapi, join(embedded, 'openapi.yaml'));
cpSync(indexHtml, join(embedded, 'index.html'));
for (const name of readdirSync(migrations)) {
  if (name.endsWith('.sql')) cpSync(join(migrations, name), join(embedded, 'migrations', name));
}

const client = await Bun.build({
  entrypoints: [clientEntry],
  outdir: join(embedded, 'assets'),
  target: 'browser',
});
if (!client.success) {
  console.error(client.logs);
  process.exit(1);
}

const emitted = Bun.spawnSync({
  cmd: [
    'bun',
    'x',
    'tsc',
    '-p',
    join(serverDir, 'tsconfig.emit.json'),
    '--pretty',
    'false',
    '--noCheck',
  ],
  cwd: repoRoot,
  stdout: 'inherit',
  stderr: 'inherit',
});
if (emitted.exitCode !== 0) process.exit(emitted.exitCode ?? 1);

const emitRoot = join(stage, 'tsc');
linkPackages(join(emitRoot, 'node_modules/@di-framework'));
process.chdir(repoRoot);
const binary = await Bun.build({
  entrypoints: [join(emitRoot, 'apps/server/src/main.js')],
  plugins: [
    {
      name: 'legacy-decorators',
      setup(build) {
        build.onResolve({ filter: /^@di-framework\/identity\// }, (args) => {
          const spec = args.path.slice('@di-framework/identity/'.length).replace(/\.ts$/, '.js');
          return { path: join(emitRoot, 'packages/core', spec) };
        });
        build.onResolve({ filter: /^@di-framework\/identity-migrations$/ }, () => ({
          path: join(emitRoot, 'packages/migrations/src/migrations.js'),
        }));
      },
    },
  ],
  compile: {
    outfile,
    autoloadDotenv: false,
    autoloadBunfig: false,
    ...(target ? { target } : {}),
    assets: ['apps/server/.compile/embedded'],
  },
});
if (!binary.success) {
  console.error(binary.logs);
  process.exit(1);
}

console.log(`identity-server ${outfile}${target ? ` (${target})` : ''}`);

function linkPackages(directory: string): void {
  mkdirSync(directory, { recursive: true });
  const links: Record<string, string> = {
    core: join(repoRoot, 'apps/api/node_modules/@di-framework/core'),
    http: join(repoRoot, 'apps/api/node_modules/@di-framework/http'),
    repo: join(repoRoot, 'apps/api/node_modules/@di-framework/repo'),
    config: join(repoRoot, 'packages/core/node_modules/@di-framework/config'),
    'identity-codegen': join(repoRoot, 'packages/codegen'),
  };
  for (const [name, target] of Object.entries(links)) {
    symlinkSync(realpathSync(target), join(directory, name));
  }
}

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
