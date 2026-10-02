/**
 * The method and result shapes of `pulumi.dynamic.ResourceProvider`, declared here so the
 * resource providers can be used and tested without loading the Pulumi engine.
 */
export interface DiffResult {
  changes: boolean;
  replaces: string[];
}

export interface CreateResult<T> {
  id: string;
  outs: T;
}

/** An `id` of undefined tells Pulumi the resource no longer exists. */
export interface ReadResult<T> {
  id?: string;
  props?: T;
}

export interface UpdateResult<T> {
  outs: T;
}

export interface ResourceProvider<Inputs, Outputs> {
  diff(id: string, olds: Outputs, news: Inputs): Promise<DiffResult>;
  create(inputs: Inputs): Promise<CreateResult<Outputs>>;
  read(id: string, props: Outputs): Promise<ReadResult<Outputs>>;
  update(id: string, olds: Outputs, news: Inputs): Promise<UpdateResult<Outputs>>;
  delete(id: string, props: Outputs): Promise<void>;
}

/** Provider configuration (`gas:issuer`, `gas:apiUrl`, `gas:provisionerClientId`, `gas:provisionerClientSecret`). */
export interface Connection {
  issuer: string;
  apiUrl?: string;
  provisionerClientId: string;
  provisionerClientSecret: string;
}

/** Every resource carries the connection and, for mutations, its URN as the Idempotency-Key. */
export interface ResourceInputs {
  connection: Connection;
  urn?: string;
}
