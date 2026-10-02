import { Component } from '@di-framework/core/decorators';
import { EntityRepository, Id, Model, Repository, type SqlDatabase } from '@di-framework/repo';
import { IDENTITY_DATABASE } from '../../shared/domain/tokens.ts';
import { PostgresAdapter } from '../../shared/infrastructure/postgres.ts';

@Model()
export class User {
  @Id()
  id!: string;

  login!: string;
  normalized_login!: string;
  email!: string | null;
  normalized_email!: string | null;
  password_hash!: string | null;
  display_name!: string;
  avatar_url!: string | null;
  email_verified!: boolean;
  status!: string;
}

@Repository()
export class UserRepository extends EntityRepository<User, string> {
  constructor(@Component(IDENTITY_DATABASE) database: SqlDatabase) {
    super(new PostgresAdapter<User, string>(database, { table: 'users' }));
  }
}
