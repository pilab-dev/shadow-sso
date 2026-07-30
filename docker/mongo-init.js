// MongoDB Initialization Script
// This script runs when MongoDB container starts for the first time
// It creates indexes and sets up the database for Shadow SSO

// Switch to the application database
db = db.getSiblingDB('shadow_sso_dev');

// Create collections with validation
db.createCollection('users', {
  validator: {
    $jsonSchema: {
      bsonType: 'object',
      required: ['email', 'status'],
      properties: {
        email: { bsonType: 'string', pattern: '^[^@]+@[^@]+\\.[^@]+$' },
        status: { enum: ['active', 'pending', 'locked', 'deactivated'] },
        firstName: { bsonType: 'string' },
        lastName: { bsonType: 'string' },
        passwordHash: { bsonType: 'string' },
        emailVerified: { bsonType: 'bool' },
        phoneNumber: { bsonType: 'string' },
        phoneVerified: { bsonType: 'bool' },
        mfaEnabled: { bsonType: 'bool' },
        createdAt: { bsonType: 'date' },
        updatedAt: { bsonType: 'date' },
        lastLoginAt: { bsonType: 'date' },
        failedLoginAttempts: { bsonType: 'int' },
        lockedUntil: { bsonType: 'date' },
        attributes: { bsonType: 'object' }
      }
    }
  }
});

// Create indexes for users collection
db.users.createIndex({ email: 1 }, { unique: true });
db.users.createIndex({ status: 1 });
db.users.createIndex({ createdAt: -1 });

// Clients collection
db.createCollection('clients', {
  validator: {
    $jsonSchema: {
      bsonType: 'object',
      required: ['id', 'name', 'type', 'isActive'],
      properties: {
        id: { bsonType: 'string' },
        name: { bsonType: 'string' },
        secret: { bsonType: 'string' },
        type: { enum: ['public', 'confidential'] },
        redirectUris: { bsonType: 'array', items: { bsonType: 'string' } },
        allowedGrantTypes: { bsonType: 'array', items: { bsonType: 'string' } },
        allowedScopes: { bsonType: 'array', items: { bsonType: 'string' } },
        isActive: { bsonType: 'bool' },
        isConfidential: { bsonType: 'bool' },
        tokenEndpointAuth: { bsonType: 'string' },
        serviceAccountRoles: { bsonType: 'array', items: { bsonType: 'string' } },
        createdAt: { bsonType: 'date' },
        updatedAt: { bsonType: 'date' }
      }
    }
  }
});

db.clients.createIndex({ id: 1 }, { unique: true });
db.clients.createIndex({ name: 1 });
db.clients.createIndex({ isActive: 1 });

// Sessions collection
db.createCollection('sessions', {
  validator: {
    $jsonSchema: {
      bsonType: 'object',
      required: ['userId', 'id', 'createdAt', 'expiresAt'],
      properties: {
        id: { bsonType: 'string' },
        userId: { bsonType: 'string' },
        clientId: { bsonType: 'string' },
        ipAddress: { bsonType: 'string' },
        userAgent: { bsonType: 'string' },
        createdAt: { bsonType: 'date' },
        expiresAt: { bsonType: 'date' },
        revokedAt: { bsonType: 'date' },
        mfaVerified: { bsonType: 'bool' }
      }
    }
  }
});

db.sessions.createIndex({ userId: 1 });
db.sessions.createIndex({ clientId: 1 });
db.sessions.createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 });
db.sessions.createIndex({ id: 1 }, { unique: true });

// OAuth Authorization Codes
db.createCollection('authorization_codes', {
  validator: {
    $jsonSchema: {
      bsonType: 'object',
      required: ['code', 'clientId', 'userId', 'redirectUri', 'expiresAt'],
      properties: {
        code: { bsonType: 'string' },
        clientId: { bsonType: 'string' },
        userId: { bsonType: 'string' },
        redirectUri: { bsonType: 'string' },
        scopes: { bsonType: 'array', items: { bsonType: 'string' } },
        codeChallenge: { bsonType: 'string' },
        codeChallengeMethod: { bsonType: 'string' },
        expiresAt: { bsonType: 'date' },
        createdAt: { bsonType: 'date' }
      }
    }
  }
});

db.authorization_codes.createIndex({ code: 1 }, { unique: true });
db.authorization_codes.createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 });

// Refresh Tokens
db.createCollection('refresh_tokens', {
  validator: {
    $jsonSchema: {
      bsonType: 'object',
      required: ['token', 'clientId', 'userId', 'expiresAt'],
      properties: {
        token: { bsonType: 'string' },
        clientId: { bsonType: 'string' },
        userId: { bsonType: 'string' },
        scopes: { bsonType: 'array', items: { bsonType: 'string' } },
        expiresAt: { bsonType: 'date' },
        createdAt: { bsonType: 'date' },
        revokedAt: { bsonType: 'date' },
        rotatedFrom: { bsonType: 'string' }
      }
    }
  }
});

db.refresh_tokens.createIndex({ token: 1 }, { unique: true });
db.refresh_tokens.createIndex({ userId: 1 });
db.refresh_tokens.createIndex({ clientId: 1 });
db.refresh_tokens.createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 });

// Access Tokens (for introspection)
db.createCollection('access_tokens', {
  validator: {
    $jsonSchema: {
      bsonType: 'object',
      required: ['token', 'clientId', 'userId', 'expiresAt'],
      properties: {
        token: { bsonType: 'string' },
        clientId: { bsonType: 'string' },
        userId: { bsonType: 'string' },
        scopes: { bsonType: 'array', items: { bsonType: 'string' } },
        expiresAt: { bsonType: 'date' },
        createdAt: { bsonType: 'date' }
      }
    }
  }
});

db.access_tokens.createIndex({ token: 1 }, { unique: true });
db.access_tokens.createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 });

// PKCE Challenges
db.createCollection('pkce_challenges', {
  validator: {
    $jsonSchema: {
      bsonType: 'object',
      required: ['codeChallenge', 'codeChallengeMethod', 'clientId', 'expiresAt'],
      properties: {
        codeChallenge: { bsonType: 'string' },
        codeChallengeMethod: { bsonType: 'string' },
        clientId: { bsonType: 'string' },
        redirectUri: { bsonType: 'string' },
        scopes: { bsonType: 'array', items: { bsonType: 'string' } },
        expiresAt: { bsonType: 'date' },
        createdAt: { bsonType: 'date' }
      }
    }
  }
});

db.pkce_challenges.createIndex({ codeChallenge: 1 }, { unique: true });
db.pkce_challenges.createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 });

// Device Authorization Codes
db.createCollection('device_codes', {
  validator: {
    $jsonSchema: {
      bsonType: 'object',
      required: ['deviceCode', 'userCode', 'clientId', 'expiresAt'],
      properties: {
        deviceCode: { bsonType: 'string' },
        userCode: { bsonType: 'string' },
        clientId: { bsonType: 'string' },
        scopes: { bsonType: 'array', items: { bsonType: 'string' } },
        expiresAt: { bsonType: 'date' },
        createdAt: { bsonType: 'date' },
        authorizedAt: { bsonType: 'date' },
        userId: { bsonType: 'string' }
      }
    }
  }
});

db.device_codes.createIndex({ deviceCode: 1 }, { unique: true });
db.device_codes.createIndex({ userCode: 1 }, { unique: true });
db.device_codes.createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 });

// Identity Providers
db.createCollection('identity_providers', {
  validator: {
    $jsonSchema: {
      bsonType: 'object',
      required: ['id', 'name', 'type', 'enabled'],
      properties: {
        id: { bsonType: 'string' },
        name: { bsonType: 'string' },
        type: { enum: ['oidc', 'saml', 'ldap'] },
        enabled: { bsonType: 'bool' },
        config: { bsonType: 'object' },
        attributeMapping: { bsonType: 'object' },
        createdAt: { bsonType: 'date' },
        updatedAt: { bsonType: 'date' }
      }
    }
  }
});

db.identity_providers.createIndex({ id: 1 }, { unique: true });
db.identity_providers.createIndex({ name: 1 });
db.identity_providers.createIndex({ enabled: 1 });

// Service Accounts
db.createCollection('service_accounts', {
  validator: {
    $jsonSchema: {
      bsonType: 'object',
      required: ['id', 'projectId', 'clientEmail', 'displayName'],
      properties: {
        id: { bsonType: 'string' },
        projectId: { bsonType: 'string' },
        clientEmail: { bsonType: 'string' },
        displayName: { bsonType: 'string' },
        description: { bsonType: 'string' },
        isActive: { bsonType: 'bool' },
        createdAt: { bsonType: 'date' },
        updatedAt: { bsonType: 'date' }
      }
    }
  }
});

db.service_accounts.createIndex({ id: 1 }, { unique: true });
db.service_accounts.createIndex({ projectId: 1 });
db.service_accounts.createIndex({ clientEmail: 1 }, { unique: true });
db.service_accounts.createIndex({ isActive: 1 });

// Service Account Keys
db.createCollection('service_account_keys', {
  validator: {
    $jsonSchema: {
      bsonType: 'object',
      required: ['id', 'serviceAccountId', 'publicKey', 'privateKey', 'algorithm', 'expiresAt'],
      properties: {
        id: { bsonType: 'string' },
        serviceAccountId: { bsonType: 'string' },
        publicKey: { bsonType: 'string' },
        privateKey: { bsonType: 'string' },
        algorithm: { bsonType: 'string' },
        expiresAt: { bsonType: 'date' },
        createdAt: { bsonType: 'date' },
        revokedAt: { bsonType: 'date' }
      }
    }
  }
});

db.service_account_keys.createIndex({ id: 1 }, { unique: true });
db.service_account_keys.createIndex({ serviceAccountId: 1 });
db.service_account_keys.createIndex({ expiresAt: 1 });

// User Federated Identities
db.createCollection('user_federated_identities', {
  validator: {
    $jsonSchema: {
      bsonType: 'object',
      required: ['userId', 'providerId', 'providerUserId'],
      properties: {
        userId: { bsonType: 'string' },
        providerId: { bsonType: 'string' },
        providerUserId: { bsonType: 'string' },
        providerData: { bsonType: 'object' },
        createdAt: { bsonType: 'date' },
        updatedAt: { bsonType: 'date' }
      }
    }
  }
});

db.user_federated_identities.createIndex({ userId: 1, providerId: 1 }, { unique: true });
db.user_federated_identities.createIndex({ providerId: 1, providerUserId: 1 }, { unique: true });

// User Attributes
db.createCollection('user_attributes', {
  validator: {
    $jsonSchema: {
      bsonType: 'object',
      required: ['userId', 'key', 'value'],
      properties: {
        userId: { bsonType: 'string' },
        key: { bsonType: 'string' },
        value: { bsonType: 'string' },
        createdAt: { bsonType: 'date' },
        updatedAt: { bsonType: 'date' }
      }
    }
  }
});

db.user_attributes.createIndex({ userId: 1, key: 1 }, { unique: true });

// Audit Logs
db.createCollection('audit_logs', {
  validator: {
    $jsonSchema: {
      bsonType: 'object',
      required: ['event', 'timestamp', 'userId'],
      properties: {
        event: { bsonType: 'string' },
        timestamp: { bsonType: 'date' },
        userId: { bsonType: 'string' },
        clientId: { bsonType: 'string' },
        ipAddress: { bsonType: 'string' },
        userAgent: { bsonType: 'string' },
        details: { bsonType: 'object' },
        success: { bsonType: 'bool' },
        errorMessage: { bsonType: 'string' }
      }
    }
  }
});

db.audit_logs.createIndex({ timestamp: -1 });
db.audit_logs.createIndex({ userId: 1, timestamp: -1 });
db.audit_logs.createIndex({ event: 1, timestamp: -1 });
db.audit_logs.createIndex({ clientId: 1, timestamp: -1 });

// Configurations
db.createCollection('configurations', {
  validator: {
    $jsonSchema: {
      bsonType: 'object',
      required: ['key', 'value'],
      properties: {
        key: { bsonType: 'string' },
        value: { bsonType: 'string' },
        description: { bsonType: 'string' },
        isEncrypted: { bsonType: 'bool' },
        createdAt: { bsonType: 'date' },
        updatedAt: { bsonType: 'date' }
      }
    }
  }
});

db.configurations.createIndex({ key: 1 }, { unique: true });

// Public Keys (JWKS)
db.createCollection('public_keys', {
  validator: {
    $jsonSchema: {
      bsonType: 'object',
      required: ['kid', 'key', 'algorithm', 'use'],
      properties: {
        kid: { bsonType: 'string' },
        key: { bsonType: 'string' },
        algorithm: { bsonType: 'string' },
        use: { enum: ['sig', 'enc'] },
        createdAt: { bsonType: 'date' },
        expiresAt: { bsonType: 'date' },
        isActive: { bsonType: 'bool' }
      }
    }
  }
});

db.public_keys.createIndex({ kid: 1 }, { unique: true });
db.public_keys.createIndex({ isActive: 1 });

print('MongoDB initialization complete for Shadow SSO');
print('Collections created with validators and indexes');