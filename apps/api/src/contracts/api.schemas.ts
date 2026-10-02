import { schemas } from '../schemas.ts';

interface RuntimeSchema {
  parse(input: unknown): unknown;
  readonly jsonSchema: Record<string, unknown>;
}

function accept(input: unknown) {
  return input;
}

function runtime(jsonSchema: object): RuntimeSchema {
  return { parse: accept, jsonSchema: jsonSchema as Record<string, unknown> };
}

function listOf(item: object): RuntimeSchema {
  return runtime({ type: 'array', items: item });
}

export const Empty = runtime({ type: 'object' });
export const MembershipRequest = runtime(schemas.MembershipRequest);
export const UpdateOAuthClientRequest = runtime(schemas.UpdateOAuthClientRequest);
export const OAuthClientResponse = runtime(schemas.OAuthClientResponse);
export const CreateUserRequest = runtime(schemas.CreateUserRequest);
export const UserCreatedResponse = runtime(schemas.UserCreatedResponse);
export const CreateOrganizationRequest = runtime(schemas.CreateOrganizationRequest);
export const OrganizationCreatedResponse = runtime(schemas.OrganizationCreatedResponse);
export const CreateOAuthClientRequest = runtime(schemas.CreateOAuthClientRequest);
export const OAuthClientSecretResponse = runtime(schemas.OAuthClientSecretResponse);
export const RotateOAuthClientSecretRequest = runtime(schemas.RotateOAuthClientSecretRequest);
export const UpdateUserRequest = runtime(schemas.UpdateUserRequest);
export const UserResponse = runtime(schemas.UserResponse);
export const UpdateOrganizationRequest = runtime(schemas.UpdateOrganizationRequest);
export const OrganizationResponse = runtime(schemas.OrganizationResponse);
export const DirectoryMembersPageResponse = runtime(schemas.DirectoryMembersPageResponse);
export const MembershipResponse = runtime(schemas.MembershipResponse);
export const Users = listOf(schemas.UserResponse);
export const Organizations = listOf(schemas.OrganizationResponse);
export const OAuthClients = listOf(schemas.OAuthClientResponse);
export const AuditRecords = listOf(schemas.AuditRecordResponse);
export const IdentityLinks = listOf(schemas.IdentityLinkView);
export const RecordResponse = runtime({
  type: 'object',
  additionalProperties: { type: 'object' },
});

export type Empty = unknown;
export type MembershipRequest = unknown;
export type UpdateOAuthClientRequest = unknown;
export type OAuthClientResponse = unknown;
export type CreateUserRequest = unknown;
export type UserCreatedResponse = unknown;
export type CreateOrganizationRequest = unknown;
export type OrganizationCreatedResponse = unknown;
export type CreateOAuthClientRequest = unknown;
export type OAuthClientSecretResponse = unknown;
export type RotateOAuthClientSecretRequest = unknown;
export type UpdateUserRequest = unknown;
export type UserResponse = unknown;
export type UpdateOrganizationRequest = unknown;
export type OrganizationResponse = unknown;
export type DirectoryMembersPageResponse = unknown;
export type MembershipResponse = unknown;
export type Users = unknown;
export type Organizations = unknown;
export type OAuthClients = unknown;
export type AuditRecords = unknown;
export type IdentityLinks = unknown;
export type RecordResponse = unknown;
