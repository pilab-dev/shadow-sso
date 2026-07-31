//go:generate go run go.uber.org/mock/mockgen@latest -source=$GOFILE -destination=mocks/mock_user_attribute_repository.go -package=mock_domain -exclude_interfaces=UserAttributeMapperRepository UserAttributeRepository
//go:generate go run go.uber.org/mock/mockgen@latest -source=$GOFILE -destination=mocks/mock_user_attribute_mapper_repository.go -package=mock_domain -exclude_interfaces=UserAttributeRepository UserAttributeMapperRepository
package domain

import (
	"context"
	"time"
)

type UserAttribute struct {
	ID     string `bson:"_id,omitempty" json:"id"`
	Name   string `bson:"name" json:"name"`
	Value  string `bson:"value" json:"value"`
	UserID string `bson:"user_id" json:"userId"`
}

type UserAttributeMapper struct {
	ID             string    `bson:"_id,omitempty" json:"id"`
	Name           string    `bson:"name" json:"name"`
	UserAttribute  string    `bson:"user_attribute" json:"userAttribute"`
	TokenClaimName string    `bson:"token_claim_name" json:"tokenClaimName"`
	TokenType      string    `bson:"token_type" json:"tokenType"`
	MultiValued    bool      `bson:"multi_valued" json:"multiValued"`
	Protocol       string    `bson:"protocol" json:"protocol"`
	ClientID       string    `bson:"client_id,omitempty" json:"clientId,omitempty"`
	CreatedAt      time.Time `bson:"created_at" json:"createdAt"`
	UpdatedAt      time.Time `bson:"updated_at" json:"updatedAt"`
}

type UserAttributeRepository interface {
	CreateAttribute(ctx context.Context, attr *UserAttribute) error
	GetAttributeByID(ctx context.Context, id string) (*UserAttribute, error)
	GetAttributesByUserID(ctx context.Context, userID string) ([]*UserAttribute, error)
	ListAllAttributes(ctx context.Context) ([]*UserAttribute, error)
	UpdateAttribute(ctx context.Context, attr *UserAttribute) error
	DeleteAttribute(ctx context.Context, id string) error
	DeleteAttributesByUserID(ctx context.Context, userID string) error
}

type UserAttributeMapperRepository interface {
	CreateMapper(ctx context.Context, mapper *UserAttributeMapper) error
	GetMapperByID(ctx context.Context, id string) (*UserAttributeMapper, error)
	GetMappersByTokenType(ctx context.Context, tokenType string) ([]*UserAttributeMapper, error)
	GetMappersForClient(ctx context.Context, clientID string, tokenType string) ([]*UserAttributeMapper, error)
	GetClientMappers(ctx context.Context, clientID string) ([]*UserAttributeMapper, error)
	ListAllMappers(ctx context.Context) ([]*UserAttributeMapper, error)
	UpdateMapper(ctx context.Context, mapper *UserAttributeMapper) error
	DeleteMapper(ctx context.Context, id string) error
}
