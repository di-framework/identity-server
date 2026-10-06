import { spawn } from 'node:child_process';
import { resolve } from 'node:path';

interface SuiteResult {
  suite: string;
  category: string;
  passed: boolean;
  totalTests: number;
  output: string;
  durationMs: number;
}

const SUITES = [
  {
    file: '01-oauth-oidc.test.ts',
    category: 'OAuth2 & OIDC Security (PKCE, Replay, Tokens, Claims)',
  },
  {
    file: '02-crypto-tokens.test.ts',
    category: 'Cryptographic & JWS Token Security (alg=none, HS256, RSA)',
  },
  {
    file: '03-api-authorization.test.ts',
    category: 'API Authorization & Access Control (BFLA, BOLA, Spoofing, Idempotency)',
  },
  {
    file: '04-session-csrf-web.test.ts',
    category: 'Web Application, Sessions & CSRF (CSRF, Open Redirect, Fixation)',
  },
  {
    file: '05-injection-traversal.test.ts',
    category: 'Path Traversal & Injection Attacks (Assets, SQLi Fuzzing)',
  },
  {
    file: '06-info-leakage-dos.test.ts',
    category: 'Information Disclosure & DoS Resilience (Metadata, Errors, Limits)',
  },
];

async function runSuite(suiteFile: string, category: string): Promise<SuiteResult> {
  const fullPath = resolve(__dirname, suiteFile);
  const startTime = Date.now();

  return new Promise((res) => {
    const proc = spawn('bun', ['test', fullPath], {
      cwd: resolve(__dirname, '../../../..'),
      env: { ...process.env },
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    let stdout = '';
    let stderr = '';

    proc.stdout.on('data', (d) => {
      stdout += d.toString();
    });
    proc.stderr.on('data', (d) => {
      stderr += d.toString();
    });

    proc.on('close', (_code) => {
      const output = stdout + stderr;
      const passMatches = output.match(/\(pass\)/g) || [];
      const failMatches = output.match(/\(fail\)/g) || [];
      const totalTests = passMatches.length + failMatches.length;
      const passed = failMatches.length === 0 && passMatches.length > 0;

      res({
        suite: suiteFile,
        category,
        passed,
        totalTests,
        output,
        durationMs: Date.now() - startTime,
      });
    });
  });
}

async function main() {
  console.log('======================================================================');
  console.log('       LIVE SECURITY RED-TEAM EVALUATION SUITE RUNNER                ');
  console.log('======================================================================\n');

  const results: SuiteResult[] = [];

  for (const suite of SUITES) {
    process.stdout.write(`Executing [${suite.file}] ... `);
    const result = await runSuite(suite.file, suite.category);
    results.push(result);
    if (result.passed) {
      console.log(`PASS (${result.totalTests} probes passed in ${result.durationMs}ms)`);
    } else {
      console.log(`FAIL (${result.totalTests} tests run in ${result.durationMs}ms)`);
    }
  }

  console.log('\n======================================================================');
  console.log('                         EVALUATION SUMMARY                           ');
  console.log('======================================================================\n');

  let totalProbes = 0;
  let allPass = true;

  for (const r of results) {
    totalProbes += r.totalTests;
    if (!r.passed) allPass = false;
    const statusTag = r.passed ? '[PASS]' : '[FAIL]';
    console.log(`${statusTag} ${r.category}`);
    console.log(`       Suite: ${r.suite} | Probes: ${r.totalTests} | Duration: ${r.durationMs}ms`);
  }

  console.log('----------------------------------------------------------------------');
  console.log(`Total Attack Probes Executed: ${totalProbes}`);
  console.log(`Overall Security Status: ${allPass ? 'ALL TESTS PASSED' : 'SOME TESTS FAILED'}`);
  console.log('======================================================================\n');

  if (!allPass) {
    console.error('Failure Details:');
    for (const r of results) {
      if (!r.passed) {
        console.error(`\n--- ${r.suite} ---`);
        console.error(r.output);
      }
    }
    process.exit(1);
  }
}

main().catch((err) => {
  console.error('Fatal error during red-team execution:', err);
  process.exit(1);
});
