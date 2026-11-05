# Migrating `ssoctl` from GraphQL to ConnectRPC

Goal: every `ssoctl` command talks to a proto-defined service. GraphQL stays for
the admin UI, but the CLI stops depending on it. Type safety first: request and
response types come from `proto/sso/v1`, not stringly-typed GraphQL documents.

## Already migrated

| Command | Before | Now |
|---|---|---|
| `session list/current` | proto | `AuthService.ListUserSessions` |
| `session kick` (`revoke`) | GraphQL `revokeSession` | `AuthService.ClearUserSessions` |
| `session kick-all` (`revoke-all`) | GraphQL `revokeAllSessions` | `AuthService.ClearUserSessions` |
| `session logout-user` | GraphQL `logoutUser` | `AuthService.ClearUserSessions` |
| `client generate-secret` | GraphQL `generateClientSecret` | `ClientManagementService.GenerateClientSecret` |
| `client generate-keys` | GraphQL `generateClientKeys` | `ClientManagementService.GenerateClientKeys` |
| `client-scope create/get/list/update/delete` | GraphQL `createClientScope`/`deleteClientScope` | `ClientScopeService` |
| `protocol-mapper create/get/list/update/delete` | — (new) | `ProtocolMapperService` |
| `oidc-config get/update` | — (new) | `OIDCConfigurationService` |

All of these use the ConnectRPC clients in `apps/sssoctl/cmd/client/client.go`.
Protocol (Connect / gRPC) is orthogonal and selectable.

## Remaining GraphQL-only commands

| Command | GraphQL operations |
|---|---|
| `realm show/update` | `realmSettings`, `updateRealm` |
| `realm-key list/update` | `realmSettings.realmKeys`, `updateRealmKeys` |
| `role list/get/create/update/delete` | `roles`, `role`, `createRole`, `updateRole`, `deleteRole` |
| `role assign-user/unassign-user` | `addRealmRoleToUser`, `removeRealmRoleFromUser` |
| `role assign-group/unassign-group` | `addRealmRoleToGroup`, `removeRealmRoleFromGroup` |
| `role mappings` | `roleMappings` |
| `role composite` | `createCompositeRole` |
| `group list/get/create/update/delete` | `groups`, `group`, `createGroup`, `updateGroup`, `deleteGroup` |
| `group members/add-member/remove-member` | `groupMembers`, `addUserToGroup`, `removeUserFromGroup` |
| `auth-flow list/get/create/update/delete` | `authenticationFlows`, `authenticationFlow`, `create/update/deleteAuthenticationFlow` |
| `auth-flow set-executions` | `authenticationExecutions`, `updateAuthenticationExecutions` |
| `user execute-actions` | `executeActions` |

`ssoctl graphql query|mutate|introspect` stays as an explicit escape hatch.

## Target proto layout

```
proto/sso/v1/role_service.proto        RoleService
proto/sso/v1/group_service.proto       GroupService
proto/sso/v1/realm_service.proto       RealmService
proto/sso/v1/client_scope_service.proto ClientScopeService
proto/sso/v1/auth_flow_service.proto   AuthFlowService
proto/sso/v1/services.proto            UserService.ExecuteActions (extension)
```

### RoleService

```proto
service RoleService {
  rpc ListRoles(ListRolesRequest) returns (ListRolesResponse);
  rpc GetRole(GetRoleRequest) returns (GetRoleResponse);
  rpc CreateRole(CreateRoleRequest) returns (CreateRoleResponse);
  rpc UpdateRole(UpdateRoleRequest) returns (UpdateRoleResponse);
  rpc DeleteRole(DeleteRoleRequest) returns (google.protobuf.Empty);
  rpc CreateCompositeRole(CreateCompositeRoleRequest) returns (CreateCompositeRoleResponse);
  rpc AssignRealmRoleToUser(AssignRealmRoleToUserRequest) returns (google.protobuf.Empty);
  rpc RemoveRealmRoleFromUser(RemoveRealmRoleFromUserRequest) returns (google.protobuf.Empty);
  rpc AssignClientRoleToUser(AssignClientRoleToUserRequest) returns (google.protobuf.Empty);
  rpc RemoveClientRoleFromUser(RemoveClientRoleFromUserRequest) returns (google.protobuf.Empty);
  rpc AssignRealmRoleToGroup(AssignRealmRoleToGroupRequest) returns (google.protobuf.Empty);
  rpc RemoveRealmRoleFromGroup(RemoveRealmRoleFromGroupRequest) returns (google.protobuf.Empty);
  rpc GetUserRoleMappings(GetUserRoleMappingsRequest) returns (GetUserRoleMappingsResponse);
}
```

### GroupService

```proto
service GroupService {
  rpc ListGroups(ListGroupsRequest) returns (ListGroupsResponse);
  rpc GetGroup(GetGroupRequest) returns (GetGroupResponse);
  rpc CreateGroup(CreateGroupRequest) returns (CreateGroupResponse);
  rpc UpdateGroup(UpdateGroupRequest) returns (UpdateGroupResponse);
  rpc DeleteGroup(DeleteGroupRequest) returns (google.protobuf.Empty);
  rpc ListGroupMembers(ListGroupMembersRequest) returns (ListGroupMembersResponse);
  rpc AddGroupMember(AddGroupMemberRequest) returns (google.protobuf.Empty);
  rpc RemoveGroupMember(RemoveGroupMemberRequest) returns (google.protobuf.Empty);
}
```

### RealmService

```proto
service RealmService {
  rpc GetRealm(GetRealmRequest) returns (GetRealmResponse);
  rpc UpdateRealm(UpdateRealmRequest) returns (UpdateRealmResponse);
  rpc ListRealmKeys(ListRealmKeysRequest) returns (ListRealmKeysResponse);
  rpc UpdateRealmKeys(UpdateRealmKeysRequest) returns (UpdateRealmKeysResponse);
}
```

`UpdateRealm` uses a `FieldMask` so the CLI can send only changed fields, instead
of the current "zero value means unchanged" convention.

### ClientScopeService

```proto
service ClientScopeService {
  rpc ListClientScopes(ListClientScopesRequest) returns (ListClientScopesResponse);
  rpc CreateClientScope(CreateClientScopeRequest) returns (CreateClientScopeResponse);
  rpc DeleteClientScope(DeleteClientScopeRequest) returns (google.protobuf.Empty);
}
```

### AuthFlowService

```proto
service AuthFlowService {
  rpc ListAuthFlows(ListAuthFlowsRequest) returns (ListAuthFlowsResponse);
  rpc GetAuthFlow(GetAuthFlowRequest) returns (GetAuthFlowResponse);
  rpc CreateAuthFlow(CreateAuthFlowRequest) returns (CreateAuthFlowResponse);
  rpc UpdateAuthFlow(UpdateAuthFlowRequest) returns (UpdateAuthFlowResponse);
  rpc DeleteAuthFlow(DeleteAuthFlowRequest) returns (google.protobuf.Empty);
  rpc GetAuthFlowExecutions(GetAuthFlowExecutionsRequest) returns (GetAuthFlowExecutionsResponse);
  rpc SetAuthFlowExecutions(SetAuthFlowExecutionsRequest) returns (google.protobuf.Empty);
}
```

### UserService.ExecuteActions

`ExecuteActions` with a typed `RequiredAction` enum (`UPDATE_PASSWORD`,
`VERIFY_EMAIL`, `CONFIGURE_TOTP`, `UPDATE_PROFILE`, …) instead of free-form
strings.

## Execution order

1. **Realm + realm keys** — smallest surface, unlocks environment bootstrap.
2. **Group** — CRUD and membership are self-contained.
3. **Role** — depends on group/user IDs; largest mapping surface.
4. **Client scopes** — done (`ClientScopeService`).
5. **Auth flows** — most complex payloads (executions).
6. **User execute-actions** — last, needs an action enum and semantics.

## Per-domain checklist

For each domain:

- [ ] add `proto/sso/v1/<domain>_service.proto`
- [ ] `buf generate --path proto/sso/v1/<domain>_service.proto`
- [ ] implement `services/<domain>_server.go` against the existing repositories
      (lift logic out of `graphql/schema.resolvers.go`, do not duplicate it)
- [ ] register the handler in `openid_config.go` with the auth/authz interceptors
- [ ] add method permissions in `internal/auth/rbac`
- [ ] add a constructor in `apps/sssoctl/cmd/client/client.go`
- [ ] rewrite the CLI commands, delete the `gqlRun` calls
- [ ] tests: handler unit tests + CLI command tests
- [ ] update `docs/cli.md` and `docs/api.md`

## Guardrails

- Do not call an RPC that mutates state without the same permission the GraphQL
  resolver enforced (`requireAdmin`, RBAC map).
- Keep error mapping: `NotFound`, `InvalidArgument`, `PermissionDenied`,
  `FailedPrecondition` — no generic `Internal` for user errors.
- Never log secrets; `GenerateClientSecret` returns plaintext exactly once.
- The GraphQL resolvers stay for the admin UI. If logic is shared, move it into a
  service and have both the resolver and the RPC handler call it.
