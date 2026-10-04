import * as pulumi from '@pulumi/pulumi';
import { portForward, runLogged } from './process';

/**
 * A container image from the local engine (Podman or Docker), published to the in-cluster
 * registry. Its `digest` output is what consumers key rollouts on.
 *
 * The engine only saves the image as an OCI layout on this machine; `oras` copies it through
 * a loopback port-forward. That works the same whether the engine runs natively or inside a
 * VM, because nothing in the VM has to reach the port-forward.
 *
 * `imageId` is the change trigger: rebuilding the local image republishes it.
 */
export interface PublishedImageInputs {
  /** Engine reference, such as `localhost/di-framework/wash:2.8.0-wasi-tls`. */
  localImage: string;
  /** `podman` or `docker`. */
  engine: string;
  /** Local image ID; a new ID means a new build. */
  imageId: string;
  /** Repository and tag in the registry, such as `di-framework/wash:2.8.0-wasi-tls`. */
  repository: string;
  registryForward: {
    kubeconfig: string;
    context?: string;
    namespace: string;
    service: string;
    localPort: number;
    remotePort: number;
  };
}

interface PublishedImageState extends PublishedImageInputs {
  digest: string;
}

type DeepInput<T> = pulumi.Input<
  T extends string | number | boolean ? T : { [K in keyof T]: DeepInput<T[K]> }
>;
type PublishedImageArgs = { [K in keyof PublishedImageInputs]: DeepInput<PublishedImageInputs[K]> };

export class PublishedImage extends pulumi.dynamic.Resource {
  /** Manifest digest in the registry. */
  declare readonly digest: pulumi.Output<string>;

  constructor(name: string, args: PublishedImageArgs, opts?: pulumi.CustomResourceOptions) {
    super(imageProvider, name, { ...args, digest: undefined }, opts);
  }
}

/** Container engine to use: the configured one, else the first of podman and docker that answers. */
export function containerEngine(configured: string | undefined): string {
  const childProcess = require('node:child_process') as typeof import('node:child_process');
  const candidates = configured ? [configured] : ['podman', 'docker'];
  for (const engine of candidates) {
    try {
      childProcess.execFileSync(engine, ['version'], { stdio: 'ignore' });
      return engine;
    } catch {
      // Try the next engine.
    }
  }
  throw new Error(`no container engine answered (${candidates.join(', ')}); set containerEngine`);
}

/** The local image ID, or a clear error naming how to get the image. */
export function localImageId(engine: string, image: string, hint: string): string {
  const childProcess = require('node:child_process') as typeof import('node:child_process');
  try {
    return childProcess
      .execFileSync(engine, ['image', 'inspect', '--format', '{{.Id}}', image], {
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'ignore'],
      })
      .trim();
  } catch {
    throw new Error(`${engine} has no image ${image}. ${hint}`);
  }
}

const imageProvider: pulumi.dynamic.ResourceProvider = {
  async diff(_id: string, olds: PublishedImageState, news: PublishedImageInputs) {
    const keys = ['localImage', 'imageId', 'repository'];
    const differs = (key: string) =>
      JSON.stringify((olds as unknown as Record<string, unknown>)[key]) !==
      JSON.stringify((news as unknown as Record<string, unknown>)[key]);
    return { changes: keys.some(differs) };
  },
  async create(inputs: PublishedImageInputs) {
    return { id: inputs.repository, outs: await publish(inputs) };
  },
  async update(_id: string, _olds: PublishedImageState, news: PublishedImageInputs) {
    return { outs: await publish(news) };
  },
  // The registry's storage goes with the registry; nothing to remove here.
  async delete() {},
};

async function publish(inputs: PublishedImageInputs): Promise<PublishedImageState> {
  const fs = require('node:fs') as typeof import('node:fs');
  const os = require('node:os') as typeof import('node:os');
  const path = require('node:path') as typeof import('node:path');
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'published-image-'));
  const log = `published-image-${inputs.repository.replace(/[^a-z0-9.-]+/gi, '-')}.log`;
  let digest: string;
  try {
    const layout = path.join(scratch, 'layout');
    if (inputs.engine.endsWith('podman')) {
      await runLogged(
        inputs.engine,
        ['save', '--format', 'oci-dir', '-o', layout, inputs.localImage],
        {
          log,
        },
      );
    } else {
      // Docker 25+ writes an OCI layout inside its save archive.
      const archive = path.join(scratch, 'image.tar');
      await runLogged(inputs.engine, ['save', '-o', archive, inputs.localImage], { log });
      fs.mkdirSync(layout);
      await runLogged('tar', ['-xf', archive, '-C', layout], { log });
    }
    const index = JSON.parse(fs.readFileSync(path.join(layout, 'index.json'), 'utf8')) as {
      manifests?: { digest?: string }[];
    };
    const manifest = index.manifests?.[0]?.digest;
    if (!manifest) throw new Error(`${inputs.localImage} saved without a manifest`);

    const forward = await portForward(inputs.registryForward);
    try {
      await runLogged(
        'oras',
        [
          'cp',
          '--from-oci-layout',
          `${layout}@${manifest}`,
          `127.0.0.1:${inputs.registryForward.localPort}/${inputs.repository}`,
          '--to-plain-http',
        ],
        { log },
      );
    } finally {
      await forward.stop();
    }
    digest = manifest;
  } finally {
    fs.rmSync(scratch, { recursive: true, force: true });
  }
  return { ...inputs, digest };
}
