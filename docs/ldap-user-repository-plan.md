# LDAP User Repository Implementation Plan

## Overview

This plan extends the existing LDAP authentication in ShadowSSO to use LDAP/Active Directory as the user store/repository. It includes three main components:
1. **LDAP User Repository** - Implements `domain.UserRepository` backed by LDAP
2. **User Property Mapper** - Maps LDAP attributes to `domain.User` fields
3. **Token Claim Mapper** - Maps LDAP groups to JWT token claims

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         ShadowSSO                                    │
├─────────────────────────────────────────────────────────────────────┤
│  TokenService ──────► LDAP User Repository (domain.UserRepository) │
│      │                              │                                │
│      ▼                              ▼                                │
│  ┌─────────┐                 ┌──────────────┐                        │
│  │  Token  │◄──────┐         │ LDAP Client │                        │
│  │  Mapper  │       │         │              │                        │
│  └─────────┘       │         └──────────────┘                        │
│      │             │                │                                 │
│      ▼             │                ▼                                 │
│  JWT Claims  ◄────┴───────► LDAP Groups ──► domain.User.Roles         │
│                              │                                        │
│                              ▼                                        │
│                       ┌──────────────────┐                          │
│                       │  Active Directory │                          │
│                       │      / LDAP       │                          │
│                       └──────────────────┘                          │
└─────────────────────────────────────────────────────────────────────┘
```

## Implementation Components

### 1. Configuration (`apps/ssso/config/config.go`)

Add LDAP user store settings:

```go
type Config struct {
    // ... existing fields ...
    
    // LDAP User Store
    LDAPUserStoreEnabled   bool   `mapstructure:"ldap_user_store_enabled"`
    LDAPUserStoreConfigID  string `mapstructure:"ldap_user_store_config_id"` // IdP ID to use
}
```

New config options:
- `SSSO_LDAP_USER_STORE_ENABLED=true/false`
- `SSSO_LDAP_USER_STORE_CONFIG_ID=<idp-name>` - Which configured LDAP IdP to use

### 2. User Property Mapper (`internal/ldap/user_property_mapper.go`)

**Purpose**: Maps LDAP attributes to `domain.User` fields based on IdP configuration.

```go
type UserPropertyMapper struct {
    // Attribute mappings from IdP config
    AttributeEmail     string
    AttributeFirstName string
    AttributeLastName  string
    AttributeUsername  string
    
    // Group to role mapping
    GroupRoleMappings map[string][]string // "cn=admins,ou=groups" -> ["admin", "user"]
}

func (m *UserPropertyMapper) ToDomainUser(entry *ldap.Entry, rawData map[string]interface{}) *domain.User
func (m *UserPropertyMapper) MapGroupsToRoles(groups []string) []string
```

**Key Features**:
- Uses existing `domain.IdentityProvider.LDAP` config for attribute mappings
- Maps LDAP groups to application roles
- Handles multiple group values

### 3. Token Claim Mapper (`internal/ldap/token_claim_mapper.go`)

**Purpose**: Maps LDAP attributes/groups to JWT token claims at token generation time.

```go
type TokenClaimMapper struct {
    ClientLdapAttributeEmail     string  // From Client config
    ClientLdapAttributeFirstName string
    ClientLdapAttributeLastName  string
    ClientLdapAttributeGroups    string
    ClientLdapCustomClaims       map[string]string // From Client config
    
    // Default fallback mappings
    DefaultEmailClaim     string
    DefaultGroupsClaim   string
}

func (m *TokenClaimMapper) MapToClaims(user *domain.User, rawData map[string]interface{}) map[string]interface{}
func (m *TokenClaimMapper) MapGroupsToTokenClaims(groups []string) []string
```

### 4. LDAP User Repository (`ldap/user_repository.go`)

Implements `domain.UserRepository` interface:

```go
type LDAPUserRepository struct {
    ldapClient           federation.LDAPClient
    idpConfig            *domain.IdentityProvider
    userPropertyMapper   *UserPropertyMapper
    
    // For MFA - separate MongoDB storage
    mfaRepo              domain.UserRepository
}
```

**Interface Methods Implementation**:

| Method | Behavior |
|--------|----------|
| `CreateUser` | Returns error (users managed in LDAP) or creates in LDAP |
| `GetUserByID` | Query LDAP by DN or custom attribute |
| `GetUserByEmail` | Query LDAP by mail attribute |
| `UpdateUser` | Update LDAP attributes (configurable: write-back or no-op) |
| `DeleteUser` | Disable user in LDAP (not delete) |
| `ListUsers` | Paginated LDAP search |
| `CountUsers` | LDAP search with count |
| MFA methods | Delegate to separate MongoDB `UserMFARepository` |

### 5. MFA Storage (Hybrid Approach)

Since LDAP doesn't store OTP secrets well, use a separate MongoDB collection:

```go
// mongodb/user_mfa_repository.go
// Stores only: userID, 2FA secrets, recovery codes
// Links to LDAP users by email/DN
```

### 6. Repository Provider Wiring (`services/repository_provider.go` or `mongodb/repository_provider.go`)

```go
type RepositoryProvider struct {
    // ... existing repos ...
    
    // LDAP User Store (conditional)
    ldapUserRepo         domain.UserRepository
    userMFAStore         domain.UserRepository // Mongo for 2FA
    
    // Current user repo (points to MongoDB or LDAP based on config)
    activeUserRepo       domain.UserRepository
}

func (p *RepositoryProvider) UserRepository(ctx context.Context) domain.UserRepository {
    if p.cfg.LDAPUserStoreEnabled && p.ldapUserRepo != nil {
        return p.ldapUserRepo
    }
    return p.mongoUserRepo
}
```

### 7. Token Service Integration

Modify `services/token_service.go` to:
1. Accept raw LDAP data from repository
2. Use `TokenClaimMapper` to build JWT claims from LDAP attributes/groups
3. Ensure `sub` claim uses stable local ID (or DN if no local mapping)

## File Changes Summary

| File | Action | Description |
|------|--------|-------------|
| `apps/ssso/config/config.go` | Modify | Add LDAP user store config |
| `internal/ldap/user_property_mapper.go` | Create | Map LDAP → domain.User |
| `internal/ldap/token_claim_mapper.go` | Create | Map LDAP → JWT claims |
| `ldap/user_repository.go` | Create | Implement domain.UserRepository |
| `mongodb/user_mfa_repository.go` | Create | Separate 2FA storage |
| `services/repository_provider.go` | Modify | Wire LDAP repo |
| `services/token_service.go` | Modify | Use TokenClaimMapper |
| `domain/repositories.go` | Modify | Document LDAP-specific behaviors |

## Decision Points

Before implementation, the following decisions need to be made:

### 1. Write-back to LDAP
Should `UpdateUser` write changes back to LDAP?
- **No (Read-only)**: ShadowSSO treats LDAP users as read-only
- **Yes**: ShadowSSO can update LDAP user attributes

### 2. User Creation
Should `CreateUser` be enabled?
- **Disabled**: Users are managed exclusively in LDAP (returns error)
- **Enabled**: Creates new user in LDAP when called from ShadowSSO

### 3. Group-to-Role Mapping
How should LDAP groups map to application roles?
- **Static mapping** (config file): E.g., `group: admins → role: admin`
- **Dynamic mapping** (client config): Use existing `ClientLDAPAttributeGroups` per client

### 4. Token Subject (`sub`)
What should the JWT `sub` claim contain?
- **LDAP DN**: Stable but long (e.g., `CN=John Doe,OU=Users,DC=example,DC=com`)
- **Email**: Human-readable but can change
- **Custom attribute**: Use a specific LDAP attribute (e.g., employeeID, uid)

### 5. Password Authentication
How should LDAP users authenticate?
- **LDAP bind only** (recommended): ShadowSSO never sees the password
- **Password hash sync**: Store password hash in MongoDB for local authentication

## Dependencies

- Uses existing `internal/federation/ldap_provider.go` for LDAP connectivity
- Uses existing `domain.IdentityProvider.LDAP` config
- Uses existing `ClientLDAPAttribute*` fields for per-client attribute mapping
