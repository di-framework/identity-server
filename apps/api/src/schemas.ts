/** Component schemas referenced by control-plane endpoint annotations. */
export const schemas = {
  MembershipRequest: {
    type: 'object',
    properties: {
      userId: {
        type: 'string',
      },
      role: {
        type: 'string',
      },
    },
  },
  UpdateOAuthClientRequest: {
    type: 'object',
    properties: {
      organizationSlug: {
        type: 'string',
      },
      redirectUris: {
        type: 'array',
        items: {
          type: 'string',
        },
        uniqueItems: true,
      },
      scopes: {
        type: 'array',
        items: {
          type: 'string',
        },
        uniqueItems: true,
      },
      browser: {
        type: 'boolean',
      },
    },
  },
  OAuthClientResponse: {
    type: 'object',
    properties: {
      client_id: {
        type: 'string',
      },
      organization_slug: {
        type: 'string',
      },
      redirect_uris: {
        type: 'array',
        items: {
          type: 'string',
        },
        uniqueItems: true,
      },
      scopes: {
        type: 'array',
        items: {
          type: 'string',
        },
        uniqueItems: true,
      },
      browser: {
        type: 'boolean',
      },
      revoked_at: {
        type: 'string',
        format: 'date-time',
      },
      created_at: {
        type: 'string',
        format: 'date-time',
      },
    },
  },
  CreateUserRequest: {
    type: 'object',
    properties: {
      login: {
        type: 'string',
      },
      email: {
        type: 'string',
      },
      displayName: {
        type: 'string',
      },
    },
  },
  UserCreatedResponse: {
    type: 'object',
    properties: {
      id: {
        type: 'string',
      },
      status: {
        type: 'string',
      },
    },
  },
  CreateOrganizationRequest: {
    type: 'object',
    properties: {
      slug: {
        type: 'string',
      },
      name: {
        type: 'string',
      },
    },
  },
  OrganizationCreatedResponse: {
    type: 'object',
    properties: {
      id: {
        type: 'string',
      },
      slug: {
        type: 'string',
      },
    },
  },
  CreateOAuthClientRequest: {
    type: 'object',
    properties: {
      clientId: {
        type: 'string',
      },
      organizationSlug: {
        type: 'string',
      },
      redirectUris: {
        type: 'array',
        items: {
          type: 'string',
        },
        uniqueItems: true,
      },
      scopes: {
        type: 'array',
        items: {
          type: 'string',
        },
        uniqueItems: true,
      },
      browser: {
        type: 'boolean',
      },
    },
  },
  OAuthClientSecretResponse: {
    type: 'object',
    properties: {
      client_id: {
        type: 'string',
      },
      client_secret: {
        type: 'string',
      },
    },
  },
  RotateOAuthClientSecretRequest: {
    type: 'object',
    properties: {
      version: {
        type: 'string',
      },
    },
  },
  UpdateUserRequest: {
    type: 'object',
    properties: {
      displayName: {
        type: 'string',
      },
    },
  },
  UserResponse: {
    type: 'object',
    properties: {
      id: {
        type: 'string',
      },
      login: {
        type: 'string',
      },
      email: {
        type: 'string',
      },
      display_name: {
        type: 'string',
      },
      email_verified: {
        type: 'boolean',
      },
      status: {
        type: 'string',
      },
    },
  },
  UpdateOrganizationRequest: {
    type: 'object',
    properties: {
      name: {
        type: 'string',
      },
    },
  },
  OrganizationResponse: {
    type: 'object',
    properties: {
      id: {
        type: 'string',
      },
      slug: {
        type: 'string',
      },
      name: {
        type: 'string',
      },
      created_at: {
        type: 'string',
        format: 'date-time',
      },
    },
  },
  DirectoryMemberResponse: {
    type: 'object',
    properties: {
      issuer: {
        type: 'string',
      },
      subject: {
        type: 'string',
      },
      login: {
        type: 'string',
      },
      display_name: {
        type: 'string',
      },
      picture: {
        type: 'string',
      },
      email: {
        type: 'string',
      },
      email_verified: {
        type: 'boolean',
      },
      organization_role: {
        type: 'string',
      },
    },
  },
  DirectoryMembersPageResponse: {
    type: 'object',
    properties: {
      items: {
        type: 'array',
        items: {
          $ref: '#/components/schemas/DirectoryMemberResponse',
        },
      },
      next_cursor: {
        type: 'string',
      },
    },
  },
  IdentityLinkView: {
    type: 'object',
    properties: {
      id: {
        type: 'string',
        format: 'uuid',
      },
      providerName: {
        type: 'string',
      },
      issuer: {
        type: 'string',
      },
      subjectHint: {
        type: 'string',
      },
      createdAt: {
        type: 'string',
        format: 'date-time',
      },
      updatedAt: {
        type: 'string',
        format: 'date-time',
      },
    },
  },
  MembershipResponse: {
    type: 'object',
    properties: {
      organization_slug: {
        type: 'string',
      },
      user_id: {
        type: 'string',
      },
      role: {
        type: 'string',
      },
    },
  },
  AuditRecordResponse: {
    type: 'object',
    properties: {
      id: {
        type: 'string',
      },
      action: {
        type: 'string',
      },
      actor_client_id: {
        type: 'string',
      },
      target: {
        type: 'string',
      },
      correlation_id: {
        type: 'string',
      },
      before_metadata: {
        type: 'string',
      },
      after_metadata: {
        type: 'string',
      },
      created_at: {
        type: 'string',
        format: 'date-time',
      },
    },
  },
} as const;
