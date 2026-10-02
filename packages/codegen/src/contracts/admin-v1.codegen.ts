import type { PlannedManifest } from '../contract.ts';
import { type UserResponse, usersResponseSchema } from './openapi.types.ts';

const users: UserResponse[] = [];

export function listUsers(): UserResponse[] {
  return users;
}

export default {
  name: 'admin',
  version: 'v1',
  http: { prefix: '/api/admin' },
  schemas: {
    Empty: { jsonSchema: { type: 'object' } },
    Users: { jsonSchema: usersResponseSchema },
  },
  operations: {
    users: {
      input: 'Empty',
      output: 'Users',
      http: { method: 'GET', path: '/users', successStatus: 200 },
    },
  },
} satisfies PlannedManifest;
