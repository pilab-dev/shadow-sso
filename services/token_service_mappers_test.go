package services

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/pilab-dev/shadow-sso/api"
	"github.com/pilab-dev/shadow-sso/cache"
	"github.com/pilab-dev/shadow-sso/domain"
	mock_domain "github.com/pilab-dev/shadow-sso/domain/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func newMapperTestService(protocolMapperRepo domain.ProtocolMapperRepository) *defaultTokenService {
	return newDefaultTokenService(
		nil,                // repo
		nil,                // cache
		"test-issuer",      // issuer
		nil,                // signer
		nil,                // pubKeyRepo
		nil,                // saRepo
		nil,                // userRepo
		nil,                // userAttrMapperRepo
		nil,                // userAttrRepo
		protocolMapperRepo, // protocolMapperRepo
		nil,                // groupRepo
		nil,                // roleRepo
	)
}

type fakeProtocolMapperRepository struct {
	mappers []*domain.ProtocolMapper
}

func newFakeProtocolMapperRepository(mappers ...*domain.ProtocolMapper) *fakeProtocolMapperRepository {
	return &fakeProtocolMapperRepository{mappers: mappers}
}

func (f *fakeProtocolMapperRepository) CreateProtocolMapper(_ context.Context, m *domain.ProtocolMapper) error {
	f.mappers = append(f.mappers, m)
	return nil
}

func (f *fakeProtocolMapperRepository) GetProtocolMapperByID(_ context.Context, id string) (*domain.ProtocolMapper, error) {
	for _, m := range f.mappers {
		if m.ID == id {
			return m, nil
		}
	}
	return nil, errors.New("protocol mapper not found")
}

func (f *fakeProtocolMapperRepository) UpdateProtocolMapper(_ context.Context, m *domain.ProtocolMapper) error {
	for i, existing := range f.mappers {
		if existing.ID == m.ID {
			f.mappers[i] = m
			return nil
		}
	}
	return errors.New("protocol mapper not found")
}

func (f *fakeProtocolMapperRepository) DeleteProtocolMapper(_ context.Context, id string) error {
	for i, m := range f.mappers {
		if m.ID == id {
			f.mappers = append(f.mappers[:i], f.mappers[i+1:]...)
			return nil
		}
	}
	return errors.New("protocol mapper not found")
}

func (f *fakeProtocolMapperRepository) ListProtocolMappers(_ context.Context) ([]*domain.ProtocolMapper, error) {
	return f.mappers, nil
}

func (f *fakeProtocolMapperRepository) ListClientProtocolMappers(_ context.Context, _ string) ([]*domain.ProtocolMapper, error) {
	return f.mappers, nil
}

type fakeTokenRepository struct{}

func (f *fakeTokenRepository) StoreToken(context.Context, *domain.Token) error { return nil }
func (f *fakeTokenRepository) GetAccessToken(context.Context, string) (*domain.Token, error) {
	return nil, nil
}
func (f *fakeTokenRepository) GetRefreshToken(context.Context, string) (*domain.Token, error) {
	return nil, nil
}
func (f *fakeTokenRepository) GetRefreshTokenInfo(context.Context, string) (*domain.TokenInfo, error) {
	return nil, nil
}
func (f *fakeTokenRepository) GetAccessTokenInfo(context.Context, string) (*domain.TokenInfo, error) {
	return nil, nil
}
func (f *fakeTokenRepository) RevokeToken(context.Context, string) error    { return nil }
func (f *fakeTokenRepository) RevokeRefreshToken(context.Context, string) error { return nil }
func (f *fakeTokenRepository) DeleteExpiredTokens(context.Context) error    { return nil }
func (f *fakeTokenRepository) GetTokenInfo(context.Context, string) (*domain.Token, error) {
	return nil, nil
}

type fakePkceRepository struct{}

func (f *fakePkceRepository) SaveCodeChallenge(context.Context, string, string) error { return nil }
func (f *fakePkceRepository) GetCodeChallenge(context.Context, string) (string, error) {
	return "", nil
}
func (f *fakePkceRepository) DeleteCodeChallenge(context.Context, string) error { return nil }

type fakeRepoProvider struct {
	tokenRepo          domain.TokenRepository
	protocolMapperRepo domain.ProtocolMapperRepository
}

func (f *fakeRepoProvider) UserRepository(context.Context) domain.UserRepository { return nil }
func (f *fakeRepoProvider) SessionRepository(context.Context) domain.SessionRepository {
	return nil
}
func (f *fakeRepoProvider) UserFederatedIdentityRepository(context.Context) domain.UserFederatedIdentityRepository {
	return nil
}
func (f *fakeRepoProvider) UserAttributeRepository(context.Context) domain.UserAttributeRepository {
	return nil
}
func (f *fakeRepoProvider) UserAttributeMapperRepository(context.Context) domain.UserAttributeMapperRepository {
	return nil
}
func (f *fakeRepoProvider) TokenRepository(context.Context) domain.TokenRepository {
	return f.tokenRepo
}
func (f *fakeRepoProvider) AuthorizationCodeRepository(context.Context) domain.AuthorizationCodeRepository {
	return nil
}
func (f *fakeRepoProvider) PkceRepository(context.Context) domain.PkceRepository { return nil }
func (f *fakeRepoProvider) DeviceAuthorizationRepository(context.Context) domain.DeviceAuthorizationRepository {
	return nil
}
func (f *fakeRepoProvider) ClientRepository(context.Context) domain.ClientRepository { return nil }
func (f *fakeRepoProvider) PublicKeyRepository(context.Context) domain.PublicKeyRepository {
	return nil
}
func (f *fakeRepoProvider) ServiceAccountRepository(context.Context) domain.ServiceAccountRepository {
	return nil
}
func (f *fakeRepoProvider) IdPRepository(context.Context) domain.IdPRepository { return nil }
func (f *fakeRepoProvider) ConfigurationRepository(context.Context) domain.ConfigurationRepository {
	return nil
}
func (f *fakeRepoProvider) GroupRepository(context.Context) domain.GroupRepository { return nil }
func (f *fakeRepoProvider) RoleRepository(context.Context) domain.RoleRepository   { return nil }
func (f *fakeRepoProvider) RealmKeysRepository(context.Context) domain.RealmKeysRepository {
	return nil
}
func (f *fakeRepoProvider) Ping(context.Context) error { return nil }
func (f *fakeRepoProvider) ProtocolMapperRepository(context.Context) domain.ProtocolMapperRepository {
	return f.protocolMapperRepo
}

func TestSetNestedClaim(t *testing.T) {
	t.Run("flat key stores value", func(t *testing.T) {
		claims := map[string]interface{}{}
		setNestedClaim(claims, "name", "alice")
		assert.Equal(t, "alice", claims["name"])
	})

	t.Run("dot notation builds nested map", func(t *testing.T) {
		claims := map[string]interface{}{}
		setNestedClaim(claims, "org.team.name", "platform")
		org, ok := claims["org"].(map[string]interface{})
		require.True(t, ok)
		team, ok := org["team"].(map[string]interface{})
		require.True(t, ok)
		assert.Equal(t, "platform", team["name"])
	})

	t.Run("existing nested map keys preserved", func(t *testing.T) {
		claims := map[string]interface{}{
			"realm_access": map[string]interface{}{"roles": []string{"user"}},
		}
		setNestedClaim(claims, "realm_access.resource", "account")
		realm, ok := claims["realm_access"].(map[string]interface{})
		require.True(t, ok)
		assert.Equal(t, []string{"user"}, realm["roles"])
		assert.Equal(t, "account", realm["resource"])
	})

	t.Run("array values appended de-duplicated", func(t *testing.T) {
		claims := map[string]interface{}{
			"realm_access": map[string]interface{}{"roles": []string{"user"}},
		}
		setNestedClaim(claims, "realm_access.roles", []string{"admin", "user"})
		realm, ok := claims["realm_access"].(map[string]interface{})
		require.True(t, ok)
		assert.Equal(t, []string{"user", "admin"}, realm["roles"])
	})
}

func TestApplyTokenMappers_ProtocolMapper_HardcodedClaimAccessAndIDToken(t *testing.T) {
	repo := newFakeProtocolMapperRepository(&domain.ProtocolMapper{
		ID:             "m1",
		Name:           "realm-groups",
		Protocol:       "openid-connect",
		ProtocolMapper: "oidc-hardcoded-claim-mapper",
		Config:         map[string]any{"claim.name": "groups", "claim.value": "developers"},
	})
	ts := newMapperTestService(repo)
	ctx := context.Background()

	for _, tokenType := range []string{api.TokenTypeAccessToken, api.TokenTypeIDToken} {
		claims := jwt.MapClaims{}
		err := ts.ApplyTokenMappers(ctx, claims, "client-1", "user-1", tokenType)
		require.NoError(t, err)
		assert.Equal(t, "developers", claims["groups"], "claim groups missing for %s", tokenType)
	}
}

func TestApplyTokenMappers_ProtocolMapper_MultivaluedArray(t *testing.T) {
	repo := newFakeProtocolMapperRepository(&domain.ProtocolMapper{
		ID:             "m2",
		Name:           "audiences",
		Protocol:       "openid-connect",
		ProtocolMapper: "oidc-hardcoded-claim-mapper",
		Config: map[string]any{
			"claim.name":  "aud",
			"claim.value": "api, web, mobile",
			"multivalued": true,
		},
	})
	ts := newMapperTestService(repo)
	claims := jwt.MapClaims{}
	err := ts.ApplyTokenMappers(context.Background(), claims, "client-1", "user-1", api.TokenTypeAccessToken)
	require.NoError(t, err)
	assert.Equal(t, []string{"api", "web", "mobile"}, claims["aud"])
}

func TestApplyTokenMappers_ProtocolMapper_NestedClaimName(t *testing.T) {
	repo := newFakeProtocolMapperRepository(&domain.ProtocolMapper{
		ID:             "m3",
		Name:           "org",
		Protocol:       "openid-connect",
		ProtocolMapper: "oidc-hardcoded-claim-mapper",
		Config:         map[string]any{"claim.name": "org.team.name", "claim.value": "platform"},
	})
	ts := newMapperTestService(repo)
	claims := jwt.MapClaims{}
	err := ts.ApplyTokenMappers(context.Background(), claims, "client-1", "user-1", api.TokenTypeAccessToken)
	require.NoError(t, err)
	org, ok := claims["org"].(map[string]interface{})
	require.True(t, ok)
	team, ok := org["team"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "platform", team["name"])
}

func TestApplyTokenMappers_UnknownProtocolMapperTypeSkipped(t *testing.T) {
	repo := newFakeProtocolMapperRepository(
		&domain.ProtocolMapper{
			ID:             "m-unknown",
			Name:           "custom",
			Protocol:       "openid-connect",
			ProtocolMapper: "oidc-some-future-mapper",
			Config:         map[string]any{"claim.name": "custom", "claim.value": "x"},
		},
		&domain.ProtocolMapper{
			ID:             "m-saml",
			Name:           "saml-attr",
			Protocol:       "saml",
			ProtocolMapper: "saml-user-attribute-mapper",
			Config:         map[string]any{"claim.name": "saml_claim", "claim.value": "y"},
		},
	)
	ts := newMapperTestService(repo)
	claims := jwt.MapClaims{}
	err := ts.ApplyTokenMappers(context.Background(), claims, "client-1", "user-1", api.TokenTypeAccessToken)
	require.NoError(t, err)
	assert.Empty(t, claims)
}

func TestApplyTokenMappers_ProtocolMapper_GroupMembership(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	groupRepo := mock_domain.NewMockGroupRepository(ctrl)
	groupRepo.EXPECT().GetGroupsByUserID(gomock.Any(), "user-1").Return([]*domain.Group{
		{ID: "g1", Name: "admins"},
		{ID: "g2", Name: "developers"},
	}, nil)

	repo := newFakeProtocolMapperRepository(&domain.ProtocolMapper{
		ID:             "m4",
		Name:           "groups",
		Protocol:       "openid-connect",
		ProtocolMapper: "oidc-group-membership-mapper",
		Config:         map[string]any{"claim.name": "groups", "multivalued": true},
	})
	ts := newDefaultTokenService(nil, nil, "test-issuer", nil, nil, nil, nil, nil, nil, repo, groupRepo, nil)
	claims := jwt.MapClaims{}
	err := ts.ApplyTokenMappers(context.Background(), claims, "client-1", "user-1", api.TokenTypeAccessToken)
	require.NoError(t, err)
	assert.Equal(t, []string{"admins", "developers"}, claims["groups"])
}

func TestApplyTokenMappers_ProtocolMapper_RealmRole(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	userRepo := mock_domain.NewMockUserRepository(ctrl)
	userRepo.EXPECT().GetUserByID(gomock.Any(), "user-1").Return(&domain.User{
		ID:    "user-1",
		Roles: []string{"admin", "user"},
	}, nil)

	repo := newFakeProtocolMapperRepository(&domain.ProtocolMapper{
		ID:             "m5",
		Name:           "roles",
		Protocol:       "openid-connect",
		ProtocolMapper: "oidc-usermodel-realm-role-mapper",
		Config:         map[string]any{"claim.name": "roles", "multivalued": true},
	})
	ts := newDefaultTokenService(nil, nil, "test-issuer", nil, nil, nil, userRepo, nil, nil, repo, nil, nil)
	claims := jwt.MapClaims{}
	err := ts.ApplyTokenMappers(context.Background(), claims, "client-1", "user-1", api.TokenTypeAccessToken)
	require.NoError(t, err)
	assert.Equal(t, []string{"admin", "user"}, claims["roles"])
}

func TestDefaultServiceProvider_TokenServiceAppliesProtocolMappers(t *testing.T) {
	provider := &fakeRepoProvider{
		tokenRepo: &fakeTokenRepository{},
		protocolMapperRepo: newFakeProtocolMapperRepository(&domain.ProtocolMapper{
			ID:             "mapper-1",
			Name:           "groups",
			Protocol:       "openid-connect",
			ProtocolMapper: "oidc-hardcoded-claim-mapper",
			Config:         map[string]any{"claim.name": "groups", "claim.value": "developers"},
		}),
	}

	signer := NewTokenSigner()
	signer.AddKeySigner("test-secret")

	sp, err := NewDefaultServiceProvider(DefaultServiceProviderOptions{
		RepositoryProvider: provider,
		Config:             &api.OpenIDProviderConfig{Issuer: "https://issuer.test"},
		TokenSigner:        signer,
		TokenCache:         cache.NewMemoryTokenStore(time.Hour),
		PkceRepository:     &fakePkceRepository{},
	})
	require.NoError(t, err)

	ts := sp.TokenService()

	token, err := ts.CreateToken(context.Background(), domain.CreateTokenOptions{
		TokenID:   "token-1",
		ClientID:  "client-1",
		UserID:    "user-1",
		TokenType: api.TokenTypeAccessToken,
		ExpireIn:  time.Hour,
		Roles:     []string{"user"},
	}, nil)
	require.NoError(t, err)
	require.NotNil(t, token)

	parsed, _, err := jwt.NewParser().ParseUnverified(token.TokenValue, jwt.MapClaims{})
	require.NoError(t, err)
	claims, ok := parsed.Claims.(jwt.MapClaims)
	require.True(t, ok)
	assert.Equal(t, "developers", claims["groups"])
}
