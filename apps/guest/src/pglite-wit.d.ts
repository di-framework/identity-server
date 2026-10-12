/** The pglite provider's WIT import, composed into the guest at build time. */
declare module 'di-framework:pglite/database@0.2.0' {
  export const open: import('@di-framework/pglite-component').WasmPgliteModule['open'];
}
