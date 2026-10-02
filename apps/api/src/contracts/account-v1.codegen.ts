import { Empty, IdentityLinks, RecordResponse } from './api.schemas.ts';
import { manifest, operation, queryParameter } from './manifest.ts';

const schema = { module: './api.schemas.ts' };
const text = { type: 'string' };

export default manifest(
  'account',
  '/api/v1/account',
  {
    Empty: { schema: Empty, ...schema },
    IdentityLinks: { schema: IdentityLinks, ...schema },
    RecordResponse: { schema: RecordResponse, ...schema },
  },
  [
    operation(
      'apiList',
      { method: 'GET', path: '/identity-links', successStatus: 200 },
      'Empty',
      'IdentityLinks',
    ),
    operation(
      'apiPrepareUnlink',
      {
        method: 'POST',
        path: '/identity-links/unlink/prepare',
        successStatus: 200,
        parameters: [queryParameter('issuer', text, true), queryParameter('subject', text, true)],
      },
      'Empty',
      'RecordResponse',
    ),
    operation(
      'apiUnlink',
      {
        method: 'DELETE',
        path: '/identity-links',
        successStatus: 200,
        parameters: [
          queryParameter('issuer', text, true),
          queryParameter('subject', text, true),
          queryParameter('confirmationToken', text, true),
        ],
      },
      'Empty',
      'RecordResponse',
    ),
  ],
);
