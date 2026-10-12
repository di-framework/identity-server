import { getBindingMetadata } from '@di-framework/bindings';
import { IdentityConfig } from '../src/bindings.ts';

/**
 * The wasi:config values compiled into the guest (`IdentityConfig` in src/bindings.ts), for tools
 * that run the guest's code outside the component: the cutover rehearsal
 * (deploy/cutover/rehearse.ts). The decorator must stay an object literal, which the platform
 * build reads statically, so the values are read back from its metadata.
 */
export function guestConfig(): Record<string, string> {
  return {
    ...((getBindingMetadata(IdentityConfig)?.options.config ?? {}) as Record<string, string>),
  };
}
