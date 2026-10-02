export class UserAccount {
  constructor(
    readonly id: string,
    readonly login: string,
    readonly email: string | null,
    readonly displayName: string,
    readonly emailVerified: boolean,
    readonly status: string,
    readonly passwordHash: string | null,
    /** `users.system_role`: `user` or `platform_admin`. Not part of the JSON user payload. */
    readonly systemRole: string = 'user',
    readonly avatarUrl: string | null = null,
  ) {}
}

export class Organization {
  constructor(
    readonly id: string,
    readonly slug: string,
    readonly name: string,
    readonly createdAt: string,
  ) {}
}

export class Membership {
  constructor(
    readonly organizationSlug: string,
    readonly userId: string,
    readonly role: string,
  ) {}
}

export class DirectoryMember {
  constructor(
    readonly id: string,
    readonly login: string,
    readonly displayName: string,
    readonly picture: string | null,
    readonly email: string | null,
    readonly emailVerified: boolean,
    readonly role: string,
  ) {}
}
