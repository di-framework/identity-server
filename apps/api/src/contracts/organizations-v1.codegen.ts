import { DirectoryMembersPageResponse, Empty } from './api.schemas.ts';
import { manifest, operation, queryParameter } from './manifest.ts';

const schema = { module: './api.schemas.ts' };

export default manifest(
  'organizations',
  '/api/v1/organizations',
  {
    Empty: { schema: Empty, ...schema },
    DirectoryMembersPageResponse: { schema: DirectoryMembersPageResponse, ...schema },
  },
  [
    operation(
      'members',
      {
        method: 'GET',
        path: '/:slug/members',
        successStatus: 200,
        summary: 'List organization members',
        description: 'Returns a paginated list of members for the specified organization slug.',
        parameters: [
          queryParameter('cursor', { type: 'string' }),
          queryParameter('limit', { type: 'integer', format: 'int32', default: 100 }),
        ],
      },
      'Empty',
      'DirectoryMembersPageResponse',
    ),
  ],
);
