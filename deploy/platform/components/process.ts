/**
 * Process helpers for the dynamic providers in this folder. They run inside Pulumi's
 * provider host, which serializes them, so Node modules are loaded at call time.
 */

export interface RunOptions {
  cwd?: string;
  env?: Record<string, string | undefined>;
  /** Log file name in the system temp directory; stderr, and stdout unless captured, go there. */
  log: string;
  /** Return stdout instead of logging it. */
  capture?: boolean;
  /** Written to stdin, so secrets never appear in an argument list. */
  input?: string;
}

/** What a finished process left behind. */
export interface RunResult {
  code: number | null;
  stdout: string;
  /** Absolute log path. */
  log: string;
  /** Last lines of the log, for error messages. */
  tail: string;
}

/**
 * Runs a binary with an argument vector (never a shell). A dynamic provider cannot
 * stream to the Pulumi console, so output goes to a log file in the temp directory.
 */
export async function runProcess(
  binary: string,
  args: string[],
  options: RunOptions,
): Promise<RunResult> {
  const childProcess = require('node:child_process') as typeof import('node:child_process');
  const fs = require('node:fs') as typeof import('node:fs');
  const os = require('node:os') as typeof import('node:os');
  const path = require('node:path') as typeof import('node:path');
  const log = path.join(os.tmpdir(), options.log);
  const logFile = fs.openSync(log, 'w');
  let stdout = '';
  let code: number | null;
  try {
    code = await new Promise<number | null>((resolve, reject) => {
      const child = childProcess.spawn(binary, args, {
        cwd: options.cwd,
        env: options.env ?? process.env,
        stdio: [
          options.input === undefined ? 'ignore' : 'pipe',
          options.capture ? 'pipe' : logFile,
          logFile,
        ],
      });
      child.stdin?.end(options.input);
      child.stdout?.on('data', (chunk: Buffer) => {
        stdout += chunk.toString('utf8');
      });
      child.on('error', reject);
      child.on('close', resolve);
    });
  } finally {
    fs.closeSync(logFile);
  }
  const tail = fs.readFileSync(log, 'utf8').trimEnd().split('\n').slice(-40).join('\n');
  return { code, stdout, log, tail };
}

/** runProcess, throwing with the log path and tail when the exit code is not zero. */
export async function runLogged(
  binary: string,
  args: string[],
  options: RunOptions,
): Promise<string> {
  const path = require('node:path') as typeof import('node:path');
  const result = await runProcess(binary, args, options);
  if (result.code !== 0) {
    throw new Error(
      `${path.basename(binary)} ${args[0]} exited with ${result.code}; log: ${result.log}\n${result.tail}`,
    );
  }
  return result.stdout;
}

/** A started `kubectl port-forward`; `stop` ends it. */
export interface PortForward {
  stop(): Promise<void>;
}

/** Forwards 127.0.0.1:<port> to a Service port and resolves once kubectl is listening. */
export async function portForward(options: {
  kubeconfig: string;
  context?: string;
  namespace: string;
  service: string;
  localPort: number;
  remotePort: number;
}): Promise<PortForward> {
  const childProcess = require('node:child_process') as typeof import('node:child_process');
  const child = childProcess.spawn(
    'kubectl',
    [
      '--kubeconfig',
      options.kubeconfig,
      ...(options.context ? ['--context', options.context] : []),
      '--namespace',
      options.namespace,
      'port-forward',
      '--address=127.0.0.1',
      `service/${options.service}`,
      `${options.localPort}:${options.remotePort}`,
    ],
    { stdio: ['ignore', 'pipe', 'pipe'] },
  );
  const exited = new Promise<void>((resolve) => child.once('close', () => resolve()));
  const stop = async () => {
    if (child.exitCode === null) child.kill();
    await exited;
  };
  let output = '';
  try {
    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('port-forward timed out')), 30_000);
      const onData = (chunk: Buffer) => {
        output += chunk.toString('utf8');
        if (output.includes('Forwarding from 127.0.0.1:')) {
          clearTimeout(timer);
          resolve();
        }
      };
      child.stdout?.on('data', onData);
      child.stderr?.on('data', onData);
      child.once('close', (code) => {
        clearTimeout(timer);
        reject(new Error(`port-forward exited with ${code} before listening:\n${output.trim()}`));
      });
    });
  } catch (error) {
    await stop();
    throw error;
  }
  // Keep draining so a long deploy cannot fill kubectl's pipes.
  child.stdout?.resume();
  child.stderr?.resume();
  return { stop };
}
