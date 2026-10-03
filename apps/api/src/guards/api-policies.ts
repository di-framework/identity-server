import { Allow, HasScope, Policy } from '@di-framework/authz';

export const ADMIN_API = 'admin-api';
export const DIRECTORY_API = 'directory-api';

/** `/api/admin/**`: reads need `admin:read`, mutations `admin:write` (`ApiController.requireScope`). */
@Policy(ADMIN_API)
export class AdminApiPolicy {
  @Allow('read')
  @HasScope('admin:read')
  read() {}

  @Allow('write')
  @HasScope('admin:write')
  write() {}
}

/** `/api/v1/organizations/{slug}/members` needs `directory:read`. */
@Policy(DIRECTORY_API)
export class DirectoryApiPolicy {
  @Allow('read')
  @HasScope('directory:read')
  read() {}
}
