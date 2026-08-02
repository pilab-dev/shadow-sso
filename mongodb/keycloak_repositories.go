package mongodb

import (
	"context"
	"fmt"
	"time"

	"github.com/pilab-dev/shadow-sso/domain"
	"github.com/rs/zerolog/log"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

const RolesCollection = "realm_roles"

// RoleRepository implements domain.RoleRepository
type RoleRepository struct {
	db    *mongo.Database
	roles *mongo.Collection
}

// NewRoleRepository creates a new RoleRepository
func NewRoleRepository(ctx context.Context, db *mongo.Database) (domain.RoleRepository, error) {
	repo := &RoleRepository{
		db:    db,
		roles: db.Collection(RolesCollection),
	}
	if err := repo.createIndexes(ctx); err != nil {
		log.Warn().Err(err).Msg("Failed to create role indexes")
	}
	return repo, nil
}

func (r *RoleRepository) createIndexes(ctx context.Context) error {
	indexModels := []mongo.IndexModel{
		{
			Keys:    bson.D{{Key: "name", Value: 1}},
			Options: options.Index().SetUnique(true),
		},
		{
			Keys: bson.D{{Key: "client_role", Value: 1}},
		},
		{
			Keys: bson.D{{Key: "container_id", Value: 1}},
		},
	}
	_, err := r.roles.Indexes().CreateMany(ctx, indexModels)
	return err
}

func (r *RoleRepository) CreateRole(ctx context.Context, role *domain.Role) error {
	if role.ID == "" {
		role.ID = NewID()
	}
	role.CreatedAt = time.Now().UTC()
	role.UpdatedAt = time.Now().UTC()
	_, err := r.roles.InsertOne(ctx, role)
	return err
}

func (r *RoleRepository) GetRoleByID(ctx context.Context, id string) (*domain.Role, error) {
	var role domain.Role
	err := r.roles.FindOne(ctx, bson.M{"_id": id}).Decode(&role)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, fmt.Errorf("role not found: %s", id)
		}
		return nil, err
	}
	return &role, nil
}

func (r *RoleRepository) GetRoleByName(ctx context.Context, name string) (*domain.Role, error) {
	var role domain.Role
	err := r.roles.FindOne(ctx, bson.M{"name": name}).Decode(&role)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, fmt.Errorf("role not found: %s", name)
		}
		return nil, err
	}
	return &role, nil
}

func (r *RoleRepository) UpdateRole(ctx context.Context, role *domain.Role) error {
	role.UpdatedAt = time.Now().UTC()
	result, err := r.roles.ReplaceOne(ctx, bson.M{"_id": role.ID}, role)
	if err != nil {
		return err
	}
	if result.MatchedCount == 0 {
		return fmt.Errorf("role not found: %s", role.ID)
	}
	return nil
}

func (r *RoleRepository) DeleteRole(ctx context.Context, id string) error {
	result, err := r.roles.DeleteOne(ctx, bson.M{"_id": id})
	if err != nil {
		return err
	}
	if result.DeletedCount == 0 {
		return fmt.Errorf("role not found: %s", id)
	}
	return nil
}

func (r *RoleRepository) ListRoles(ctx context.Context) ([]*domain.Role, error) {
	cursor, err := r.roles.Find(ctx, bson.M{})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var roles []*domain.Role
	if err := cursor.All(ctx, &roles); err != nil {
		return nil, err
	}
	return roles, nil
}

func (r *RoleRepository) ListRealmRoles(ctx context.Context) ([]*domain.Role, error) {
	cursor, err := r.roles.Find(ctx, bson.M{"client_role": false})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var roles []*domain.Role
	if err := cursor.All(ctx, &roles); err != nil {
		return nil, err
	}
	return roles, nil
}

func (r *RoleRepository) ListClientRoles(ctx context.Context, clientID string) ([]*domain.Role, error) {
	cursor, err := r.roles.Find(ctx, bson.M{"client_role": true, "container_id": clientID})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var roles []*domain.Role
	if err := cursor.All(ctx, &roles); err != nil {
		return nil, err
	}
	return roles, nil
}

func (r *RoleRepository) AddChildRole(ctx context.Context, parentID, childID string) error {
	return r.roles.FindOneAndUpdate(
		ctx,
		bson.M{"_id": parentID},
		bson.M{"$addToSet": bson.M{"child_roles": childID}},
	).Err()
}

func (r *RoleRepository) RemoveChildRole(ctx context.Context, parentID, childID string) error {
	return r.roles.FindOneAndUpdate(
		ctx,
		bson.M{"_id": parentID},
		bson.M{"$pull": bson.M{"child_roles": childID}},
	).Err()
}

const GroupsCollection = "realm_groups"

// GroupRepository implements domain.GroupRepository
type GroupRepository struct {
	db     *mongo.Database
	groups *mongo.Collection
}

// NewGroupRepository creates a new GroupRepository
func NewGroupRepository(ctx context.Context, db *mongo.Database) (domain.GroupRepository, error) {
	repo := &GroupRepository{
		db:     db,
		groups: db.Collection(GroupsCollection),
	}
	if err := repo.createIndexes(ctx); err != nil {
		log.Warn().Err(err).Msg("Failed to create group indexes")
	}
	return repo, nil
}

func (r *GroupRepository) createIndexes(ctx context.Context) error {
	indexModels := []mongo.IndexModel{
		{
			Keys:    bson.D{{Key: "path", Value: 1}},
			Options: options.Index().SetUnique(true),
		},
		{
			Keys: bson.D{{Key: "member_ids", Value: 1}},
		},
	}
	_, err := r.groups.Indexes().CreateMany(ctx, indexModels)
	return err
}

func (r *GroupRepository) CreateGroup(ctx context.Context, group *domain.Group) error {
	if group.ID == "" {
		group.ID = NewID()
	}
	group.CreatedAt = time.Now().UTC()
	group.UpdatedAt = time.Now().UTC()
	_, err := r.groups.InsertOne(ctx, group)
	return err
}

func (r *GroupRepository) GetGroupByID(ctx context.Context, id string) (*domain.Group, error) {
	var group domain.Group
	err := r.groups.FindOne(ctx, bson.M{"_id": id}).Decode(&group)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, fmt.Errorf("group not found: %s", id)
		}
		return nil, err
	}
	return &group, nil
}

func (r *GroupRepository) GetGroupByPath(ctx context.Context, path string) (*domain.Group, error) {
	var group domain.Group
	err := r.groups.FindOne(ctx, bson.M{"path": path}).Decode(&group)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, fmt.Errorf("group not found: %s", path)
		}
		return nil, err
	}
	return &group, nil
}

func (r *GroupRepository) UpdateGroup(ctx context.Context, group *domain.Group) error {
	group.UpdatedAt = time.Now().UTC()
	result, err := r.groups.ReplaceOne(ctx, bson.M{"_id": group.ID}, group)
	if err != nil {
		return err
	}
	if result.MatchedCount == 0 {
		return fmt.Errorf("group not found: %s", group.ID)
	}
	return nil
}

func (r *GroupRepository) DeleteGroup(ctx context.Context, id string) error {
	result, err := r.groups.DeleteOne(ctx, bson.M{"_id": id})
	if err != nil {
		return err
	}
	if result.DeletedCount == 0 {
		return fmt.Errorf("group not found: %s", id)
	}
	return nil
}

func (r *GroupRepository) ListGroups(ctx context.Context) ([]*domain.Group, error) {
	cursor, err := r.groups.Find(ctx, bson.M{})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var groups []*domain.Group
	if err := cursor.All(ctx, &groups); err != nil {
		return nil, err
	}
	return groups, nil
}

func (r *GroupRepository) AddMember(ctx context.Context, groupID, userID string) error {
	return r.groups.FindOneAndUpdate(
		ctx,
		bson.M{"_id": groupID},
		bson.M{"$addToSet": bson.M{"member_ids": userID}},
	).Err()
}

func (r *GroupRepository) RemoveMember(ctx context.Context, groupID, userID string) error {
	return r.groups.FindOneAndUpdate(
		ctx,
		bson.M{"_id": groupID},
		bson.M{"$pull": bson.M{"member_ids": userID}},
	).Err()
}

func (r *GroupRepository) GetMemberCount(ctx context.Context, groupID string) (int64, error) {
	group, err := r.GetGroupByID(ctx, groupID)
	if err != nil {
		return 0, err
	}
	return int64(len(group.MemberIDs)), nil
}

func (r *GroupRepository) GetGroupsByUserID(ctx context.Context, userID string) ([]*domain.Group, error) {
	cursor, err := r.groups.Find(ctx, bson.M{"member_ids": userID})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var groups []*domain.Group
	if err := cursor.All(ctx, &groups); err != nil {
		return nil, err
	}
	if groups == nil {
		groups = []*domain.Group{}
	}
	return groups, nil
}

func (r *GroupRepository) AddRealmRole(ctx context.Context, groupID, roleID string) error {
	return r.groups.FindOneAndUpdate(
		ctx,
		bson.M{"_id": groupID},
		bson.M{"$addToSet": bson.M{"realm_roles": roleID}},
	).Err()
}

func (r *GroupRepository) RemoveRealmRole(ctx context.Context, groupID, roleID string) error {
	return r.groups.FindOneAndUpdate(
		ctx,
		bson.M{"_id": groupID},
		bson.M{"$pull": bson.M{"realm_roles": roleID}},
	).Err()
}

func (r *GroupRepository) AddClientRole(ctx context.Context, groupID, clientID, roleID string) error {
	key := "client_roles." + clientID
	return r.groups.FindOneAndUpdate(
		ctx,
		bson.M{"_id": groupID},
		bson.M{"$addToSet": bson.M{key: roleID}},
	).Err()
}

func (r *GroupRepository) RemoveClientRole(ctx context.Context, groupID, clientID, roleID string) error {
	key := "client_roles." + clientID
	return r.groups.FindOneAndUpdate(
		ctx,
		bson.M{"_id": groupID},
		bson.M{"$pull": bson.M{key: roleID}},
	).Err()
}

const ProtocolMappersCollection = "protocol_mappers"

// ProtocolMapperRepository implements domain.ProtocolMapperRepository
type ProtocolMapperRepository struct {
	db      *mongo.Database
	mappers *mongo.Collection
}

// NewProtocolMapperRepository creates a new ProtocolMapperRepository
func NewProtocolMapperRepository(ctx context.Context, db *mongo.Database) (domain.ProtocolMapperRepository, error) {
	repo := &ProtocolMapperRepository{
		db:      db,
		mappers: db.Collection(ProtocolMappersCollection),
	}
	if err := repo.createIndexes(ctx); err != nil {
		log.Warn().Err(err).Msg("Failed to create protocol mapper indexes")
	}
	return repo, nil
}

func (r *ProtocolMapperRepository) createIndexes(ctx context.Context) error {
	indexModels := []mongo.IndexModel{
		{
			Keys: bson.D{{Key: "client_id", Value: 1}},
		},
	}
	_, err := r.mappers.Indexes().CreateMany(ctx, indexModels)
	return err
}

func (r *ProtocolMapperRepository) CreateProtocolMapper(ctx context.Context, mapper *domain.ProtocolMapper) error {
	if mapper.ID == "" {
		mapper.ID = NewID()
	}
	mapper.CreatedAt = time.Now().UTC()
	mapper.UpdatedAt = time.Now().UTC()
	_, err := r.mappers.InsertOne(ctx, mapper)
	return err
}

func (r *ProtocolMapperRepository) GetProtocolMapperByID(ctx context.Context, id string) (*domain.ProtocolMapper, error) {
	var mapper domain.ProtocolMapper
	err := r.mappers.FindOne(ctx, bson.M{"_id": id}).Decode(&mapper)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, fmt.Errorf("protocol mapper not found: %s", id)
		}
		return nil, err
	}
	return &mapper, nil
}

func (r *ProtocolMapperRepository) UpdateProtocolMapper(ctx context.Context, mapper *domain.ProtocolMapper) error {
	mapper.UpdatedAt = time.Now().UTC()
	result, err := r.mappers.ReplaceOne(ctx, bson.M{"_id": mapper.ID}, mapper)
	if err != nil {
		return err
	}
	if result.MatchedCount == 0 {
		return fmt.Errorf("protocol mapper not found: %s", mapper.ID)
	}
	return nil
}

func (r *ProtocolMapperRepository) DeleteProtocolMapper(ctx context.Context, id string) error {
	result, err := r.mappers.DeleteOne(ctx, bson.M{"_id": id})
	if err != nil {
		return err
	}
	if result.DeletedCount == 0 {
		return fmt.Errorf("protocol mapper not found: %s", id)
	}
	return nil
}

func (r *ProtocolMapperRepository) ListProtocolMappers(ctx context.Context) ([]*domain.ProtocolMapper, error) {
	cursor, err := r.mappers.Find(ctx, bson.M{})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var mappers []*domain.ProtocolMapper
	if err := cursor.All(ctx, &mappers); err != nil {
		return nil, err
	}
	return mappers, nil
}

func (r *ProtocolMapperRepository) ListClientProtocolMappers(ctx context.Context, clientID string) ([]*domain.ProtocolMapper, error) {
	cursor, err := r.mappers.Find(ctx, bson.M{"client_id": clientID})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var mappers []*domain.ProtocolMapper
	if err := cursor.All(ctx, &mappers); err != nil {
		return nil, err
	}
	return mappers, nil
}

const AuthFlowsCollection = "auth_flows"

// AuthenticationFlowRepository implements domain.AuthenticationFlowRepository
type AuthenticationFlowRepository struct {
	db     *mongo.Database
	flows  *mongo.Collection
	execs  *mongo.Collection
}

// NewAuthenticationFlowRepository creates a new AuthenticationFlowRepository
func NewAuthenticationFlowRepository(ctx context.Context, db *mongo.Database) (domain.AuthenticationFlowRepository, error) {
	repo := &AuthenticationFlowRepository{
		db:    db,
		flows: db.Collection(AuthFlowsCollection),
		execs: db.Collection("auth_executions"),
	}
	if err := repo.createIndexes(ctx); err != nil {
		log.Warn().Err(err).Msg("Failed to create auth flow indexes")
	}
	return repo, nil
}

func (r *AuthenticationFlowRepository) createIndexes(ctx context.Context) error {
	indexModels := []mongo.IndexModel{
		{
			Keys:    bson.D{{Key: "alias", Value: 1}},
			Options: options.Index().SetUnique(true),
		},
		{
			Keys: bson.D{{Key: "flow_id", Value: 1}},
		},
	}
	_, err := r.flows.Indexes().CreateMany(ctx, indexModels)
	return err
}

func (r *AuthenticationFlowRepository) CreateFlow(ctx context.Context, flow *domain.AuthenticationFlow) error {
	if flow.ID == "" {
		flow.ID = NewID()
	}
	flow.CreatedAt = time.Now().UTC()
	flow.UpdatedAt = time.Now().UTC()
	_, err := r.flows.InsertOne(ctx, flow)
	return err
}

func (r *AuthenticationFlowRepository) GetFlowByID(ctx context.Context, id string) (*domain.AuthenticationFlow, error) {
	var flow domain.AuthenticationFlow
	err := r.flows.FindOne(ctx, bson.M{"_id": id}).Decode(&flow)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, fmt.Errorf("flow not found: %s", id)
		}
		return nil, err
	}
	return &flow, nil
}

func (r *AuthenticationFlowRepository) GetFlowByAlias(ctx context.Context, alias string) (*domain.AuthenticationFlow, error) {
	var flow domain.AuthenticationFlow
	err := r.flows.FindOne(ctx, bson.M{"alias": alias}).Decode(&flow)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, fmt.Errorf("flow not found: %s", alias)
		}
		return nil, err
	}
	return &flow, nil
}

func (r *AuthenticationFlowRepository) UpdateFlow(ctx context.Context, flow *domain.AuthenticationFlow) error {
	flow.UpdatedAt = time.Now().UTC()
	result, err := r.flows.ReplaceOne(ctx, bson.M{"_id": flow.ID}, flow)
	if err != nil {
		return err
	}
	if result.MatchedCount == 0 {
		return fmt.Errorf("flow not found: %s", flow.ID)
	}
	return nil
}

func (r *AuthenticationFlowRepository) DeleteFlow(ctx context.Context, id string) error {
	result, err := r.flows.DeleteOne(ctx, bson.M{"_id": id})
	if err != nil {
		return err
	}
	if result.DeletedCount == 0 {
		return fmt.Errorf("flow not found: %s", id)
	}
	return nil
}

func (r *AuthenticationFlowRepository) ListFlows(ctx context.Context) ([]*domain.AuthenticationFlow, error) {
	cursor, err := r.flows.Find(ctx, bson.M{})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var flows []*domain.AuthenticationFlow
	if err := cursor.All(ctx, &flows); err != nil {
		return nil, err
	}
	return flows, nil
}

func (r *AuthenticationFlowRepository) UpsertExecution(ctx context.Context, exec *domain.AuthenticationExecution) error {
	if exec.ID == "" {
		exec.ID = NewID()
	}
	filter := bson.M{"_id": exec.ID}
	if exec.ID == "" {
		// For new executions, use flow_id + authenticator as unique key
		filter = bson.M{"flow_id": exec.FlowID, "authenticator": exec.Authenticator}
	}
	opts := options.FindOneAndUpdate().SetUpsert(true)
	err := r.execs.FindOneAndUpdate(ctx, filter, bson.M{"$set": exec}, opts).Err()
	return err
}

func (r *AuthenticationFlowRepository) GetExecutions(ctx context.Context, flowID string) ([]*domain.AuthenticationExecution, error) {
	cursor, err := r.execs.Find(ctx, bson.M{"flow_id": flowID})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var execs []*domain.AuthenticationExecution
	if err := cursor.All(ctx, &execs); err != nil {
		return nil, err
	}
	return execs, nil
}

func (r *AuthenticationFlowRepository) DeleteExecution(ctx context.Context, id string) error {
	result, err := r.execs.DeleteOne(ctx, bson.M{"_id": id})
	if err != nil {
		return err
	}
	if result.DeletedCount == 0 {
		return fmt.Errorf("execution not found: %s", id)
	}
	return nil
}

const ClientScopesCollection = "client_scopes"

// ClientScopeRepository implements domain.ClientScopeRepository
type ClientScopeRepository struct {
	db     *mongo.Database
	scopes *mongo.Collection
}

// NewClientScopeRepository creates a new ClientScopeRepository
func NewClientScopeRepository(ctx context.Context, db *mongo.Database) (domain.ClientScopeRepository, error) {
	repo := &ClientScopeRepository{
		db:     db,
		scopes: db.Collection(ClientScopesCollection),
	}
	return repo, nil
}

func (r *ClientScopeRepository) CreateClientScope(ctx context.Context, scope *domain.ClientScope) error {
	if scope.ID == "" {
		scope.ID = NewID()
	}
	scope.CreatedAt = time.Now().UTC()
	_, err := r.scopes.InsertOne(ctx, scope)
	return err
}

func (r *ClientScopeRepository) GetClientScopeByID(ctx context.Context, id string) (*domain.ClientScope, error) {
	var scope domain.ClientScope
	err := r.scopes.FindOne(ctx, bson.M{"_id": id}).Decode(&scope)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, fmt.Errorf("client scope not found: %s", id)
		}
		return nil, err
	}
	return &scope, nil
}

func (r *ClientScopeRepository) UpdateClientScope(ctx context.Context, scope *domain.ClientScope) error {
	result, err := r.scopes.ReplaceOne(ctx, bson.M{"_id": scope.ID}, scope)
	if err != nil {
		return err
	}
	if result.MatchedCount == 0 {
		return fmt.Errorf("client scope not found: %s", scope.ID)
	}
	return nil
}

func (r *ClientScopeRepository) DeleteClientScope(ctx context.Context, id string) error {
	result, err := r.scopes.DeleteOne(ctx, bson.M{"_id": id})
	if err != nil {
		return err
	}
	if result.DeletedCount == 0 {
		return fmt.Errorf("client scope not found: %s", id)
	}
	return nil
}

const RealmSettingsCollection = "realm_settings"

// RealmSettingsRepository implements domain.RealmSettingsRepository
type RealmSettingsRepository struct {
	db       *mongo.Database
	settings *mongo.Collection
}

// NewRealmSettingsRepository creates a new RealmSettingsRepository
func NewRealmSettingsRepository(ctx context.Context, db *mongo.Database) (domain.RealmSettingsRepository, error) {
	repo := &RealmSettingsRepository{
		db:       db,
		settings: db.Collection(RealmSettingsCollection),
	}
	return repo, nil
}

func (r *RealmSettingsRepository) GetRealmSettings(ctx context.Context) (*domain.RealmSettings, error) {
	result := r.settings.FindOne(ctx, bson.M{})

	// Get raw BSON to handle string _id
	raw, err := result.Raw()
	if err != nil {
		if err == mongo.ErrNoDocuments {
			// Return default settings if none exist
			return &domain.RealmSettings{
				Realm:               "master",
				DisplayName:         "Shadow SSO",
				Enabled:             true,
				BruteForceProtected: true,
				SSLRequired:         "external",
				AccessTokenLifespan: 300,
				AccessCodeLifespan:  60,
			}, nil
		}
		return nil, err
	}

	settings := &domain.RealmSettings{}
	if err := bson.Unmarshal(raw, settings); err != nil {
		return nil, err
	}

	return settings, nil
}

func (r *RealmSettingsRepository) UpdateRealmSettings(ctx context.Context, s *domain.RealmSettings) error {
	s.UpdatedAt = time.Now().UTC()

	// Use string ID to ensure it's stored as string
	if s.ID == "" {
		s.ID = "master"
	}

	// Delete existing and re-insert to ensure clean state
	_, err := r.settings.DeleteOne(ctx, bson.M{})
	if err != nil && err != mongo.ErrNoDocuments {
		return err
	}

	_, err = r.settings.InsertOne(ctx, s)
	return err
}

const RealmKeysCollection = "realm_keys"

// RealmKeysRepository implements domain.RealmKeysRepository
type RealmKeysRepository struct {
	db    *mongo.Database
	keys  *mongo.Collection
}

// NewRealmKeysRepository creates a new RealmKeysRepository
func NewRealmKeysRepository(ctx context.Context, db *mongo.Database) (domain.RealmKeysRepository, error) {
	repo := &RealmKeysRepository{
		db:   db,
		keys: db.Collection(RealmKeysCollection),
	}
	return repo, nil
}

func (r *RealmKeysRepository) ListRealmKeys(ctx context.Context) ([]*domain.RealmKey, error) {
	return r.find(ctx, bson.M{"client_id": ""})
}

func (r *RealmKeysRepository) ListClientKeys(ctx context.Context, clientID string) ([]*domain.RealmKey, error) {
	return r.find(ctx, bson.M{"client_id": clientID})
}

func (r *RealmKeysRepository) ListAllKeys(ctx context.Context) ([]*domain.RealmKey, error) {
	return r.find(ctx, bson.M{})
}

func (r *RealmKeysRepository) find(ctx context.Context, filter bson.M) ([]*domain.RealmKey, error) {
	cursor, err := r.keys.Find(ctx, filter)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var keys []*domain.RealmKey
	if err := cursor.All(ctx, &keys); err != nil {
		return nil, err
	}
	return keys, nil
}

// SaveRealmKey creates or updates a single key without touching others.
func (r *RealmKeysRepository) SaveRealmKey(ctx context.Context, key *domain.RealmKey) error {
	if key.ID == "" {
		key.ID = NewID()
	}
	if key.CreatedAt.IsZero() {
		key.CreatedAt = time.Now().UTC()
	}
	_, err := r.keys.ReplaceOne(ctx, bson.M{"_id": key.ID}, key, options.Replace().SetUpsert(true))
	return err
}

// UpdateRealmKeyStatus transitions a single key to a new lifecycle status,
// keeping the legacy Active bool in sync for GraphQL schema compatibility.
func (r *RealmKeysRepository) UpdateRealmKeyStatus(ctx context.Context, keyID string, status domain.RealmKeyStatus) error {
	_, err := r.keys.UpdateOne(ctx,
		bson.M{"_id": keyID},
		bson.M{"$set": bson.M{"status": status, "active": status == domain.RealmKeyStatusActive}},
	)
	return err
}

// UpdateRealmKeys bulk-replaces the realm-default key set (ClientID == "")
// only — client-specific keys are left untouched.
func (r *RealmKeysRepository) UpdateRealmKeys(ctx context.Context, keys []*domain.RealmKey) error {
	_, err := r.keys.DeleteMany(ctx, bson.M{"client_id": ""})
	if err != nil {
		return err
	}
	if len(keys) == 0 {
		return nil
	}
	docs := make([]interface{}, len(keys))
	for i, k := range keys {
		if k.ID == "" {
			k.ID = NewID()
		}
		k.ClientID = ""
		docs[i] = k
	}
	_, err = r.keys.InsertMany(ctx, docs)
	return err
}
// SeedDefaultRealmRoles ensures the given role names exist as realm role
// documents. Existing roles are left untouched, making the seed idempotent.
func SeedDefaultRealmRoles(ctx context.Context, roleRepo domain.RoleRepository, names ...string) error {
	for _, name := range names {
		existing, err := roleRepo.GetRoleByName(ctx, name)
		if err == nil && existing != nil {
			continue
		}
		now := time.Now().UTC()
		role := &domain.Role{
			ID:         NewID(),
			Name:       name,
			ClientRole: false,
			CreatedAt:  now,
			UpdatedAt:  now,
		}
		if err := roleRepo.CreateRole(ctx, role); err != nil {
			return fmt.Errorf("failed to seed realm role %q: %w", name, err)
		}
	}
	return nil
}

// SeedDefaultGroup ensures a group with the given name and path exists.
// An existing group at the same path is left untouched (idempotent).
func SeedDefaultGroup(ctx context.Context, groupRepo domain.GroupRepository, name, path string) error {
	existing, err := groupRepo.GetGroupByPath(ctx, path)
	if err == nil && existing != nil {
		return nil
	}
	group := &domain.Group{
		ID:   NewID(),
		Name: name,
		Path: path,
	}
	if err := groupRepo.CreateGroup(ctx, group); err != nil {
		return fmt.Errorf("failed to seed default group %q: %w", path, err)
	}
	return nil
}
