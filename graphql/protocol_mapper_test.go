package graphql_test

import (
	"context"
	"errors"
	"testing"

	"github.com/pilab-dev/shadow-sso/domain"
	"github.com/pilab-dev/shadow-sso/graphql"
	"github.com/stretchr/testify/require"
)

// inMemoryProtocolMapperRepository is a tiny fake that mirrors the effective
// client query semantics of the Mongo implementation: client-specific mappers
// plus realm-wide ones (no client ID).
type inMemoryProtocolMapperRepository struct {
	mappers []*domain.ProtocolMapper
}

func (f *inMemoryProtocolMapperRepository) CreateProtocolMapper(_ context.Context, m *domain.ProtocolMapper) error {
	if m.ID == "" {
		m.ID = "mapper-" + m.Name
	}
	f.mappers = append(f.mappers, m)
	return nil
}

func (f *inMemoryProtocolMapperRepository) GetProtocolMapperByID(_ context.Context, id string) (*domain.ProtocolMapper, error) {
	for _, m := range f.mappers {
		if m.ID == id {
			return m, nil
		}
	}
	return nil, errors.New("protocol mapper not found")
}

func (f *inMemoryProtocolMapperRepository) UpdateProtocolMapper(_ context.Context, m *domain.ProtocolMapper) error {
	for i, existing := range f.mappers {
		if existing.ID == m.ID {
			f.mappers[i] = m
			return nil
		}
	}
	return errors.New("protocol mapper not found")
}

func (f *inMemoryProtocolMapperRepository) DeleteProtocolMapper(_ context.Context, id string) error {
	for i, m := range f.mappers {
		if m.ID == id {
			f.mappers = append(f.mappers[:i], f.mappers[i+1:]...)
			return nil
		}
	}
	return errors.New("protocol mapper not found")
}

func (f *inMemoryProtocolMapperRepository) ListProtocolMappers(_ context.Context) ([]*domain.ProtocolMapper, error) {
	return f.mappers, nil
}

func (f *inMemoryProtocolMapperRepository) ListClientProtocolMappers(_ context.Context, clientID string) ([]*domain.ProtocolMapper, error) {
	out := make([]*domain.ProtocolMapper, 0, len(f.mappers))
	for _, m := range f.mappers {
		if m.ClientID == "" || m.ClientID == clientID {
			out = append(out, m)
		}
	}
	return out, nil
}

func (f *inMemoryProtocolMapperRepository) ListRealmProtocolMappers(_ context.Context) ([]*domain.ProtocolMapper, error) {
	out := make([]*domain.ProtocolMapper, 0, len(f.mappers))
	for _, m := range f.mappers {
		if m.ClientID == "" {
			out = append(out, m)
		}
	}
	return out, nil
}

func ptr[T any](v T) *T { return &v }

func TestCreateProtocolMapper_PersistsClientID(t *testing.T) {
	repo := &inMemoryProtocolMapperRepository{}
	resolver := &graphql.Resolver{ProtocolMapperRepo: repo}
	ctx := context.Background()

	created, err := resolver.Mutation().CreateProtocolMapper(ctx, graphql.CreateProtocolMapperInput{
		Name:           "email-claim",
		Protocol:       "openid-connect",
		ProtocolMapper: "oidc-usermodel-attribute-mapper",
		ClientID:       ptr("client-a"),
	})
	require.NoError(t, err)
	require.Equal(t, "client-a", created.ClientID)
	require.Equal(t, "client-a", repo.mappers[0].ClientID, "the token service only sees mappers stored with a client id")

	realmWide, err := resolver.Mutation().CreateProtocolMapper(ctx, graphql.CreateProtocolMapperInput{
		Name:           "realm-claim",
		Protocol:       "openid-connect",
		ProtocolMapper: "oidc-hardcoded-claim-mapper",
	})
	require.NoError(t, err)
	require.Empty(t, realmWide.ClientID, "an omitted clientId must create a realm-wide mapper")

	applies, err := resolver.Query().ClientTokenMappers(ctx, "client-b")
	require.NoError(t, err)
	require.Len(t, applies, 1)
	require.Equal(t, "realm-claim", applies[0].Name)

	realmOnly, err := resolver.Query().RealmTokenMappers(ctx)
	require.NoError(t, err)
	require.Len(t, realmOnly, 1)
	require.Equal(t, "realm-claim", realmOnly[0].Name)
}

func TestUpdateProtocolMapper_MovesBetweenClientAndRealm(t *testing.T) {
	repo := &inMemoryProtocolMapperRepository{
		mappers: []*domain.ProtocolMapper{{
			ID:             "mapper-1",
			Name:           "claim",
			Protocol:       "openid-connect",
			ProtocolMapper: "oidc-hardcoded-claim-mapper",
			ClientID:       "client-a",
		}},
	}
	resolver := &graphql.Resolver{ProtocolMapperRepo: repo}
	ctx := context.Background()

	updated, err := resolver.Mutation().UpdateProtocolMapper(ctx, "mapper-1", graphql.UpdateProtocolMapperInput{
		ClientID: ptr(""),
	})
	require.NoError(t, err)
	require.Empty(t, updated.ClientID)

	realmOnly, err := resolver.Query().RealmTokenMappers(ctx)
	require.NoError(t, err)
	require.Len(t, realmOnly, 1)
	require.Equal(t, "mapper-1", realmOnly[0].ID)
}
