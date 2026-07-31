package services

import (
	"context"
	"errors"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/pilab-dev/shadow-sso/domain"
	mock_domain "github.com/pilab-dev/shadow-sso/domain/mocks"
	ssov1 "github.com/pilab-dev/shadow-sso/gen/proto/sso/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.uber.org/mock/gomock"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// TestUserAttributeServiceServer_CreateUserAttribute covers the create path:
// validation (user_id/name/value required), repo error mapping and the proto
// conversion of the created attribute (no timestamps in domain).
func TestUserAttributeServiceServer_CreateUserAttribute(t *testing.T) {
	tests := []struct {
		name     string
		reqMsg   *ssov1.CreateUserAttributeRequest
		setup    func(t *testing.T, attrRepo *mock_domain.MockUserAttributeRepository)
		wantErr  bool
		wantCode connect.Code
	}{
		{
			name:   "creates attribute successfully",
			reqMsg: &ssov1.CreateUserAttributeRequest{UserId: "u1", Name: "email", Value: "e@example.com"},
			setup: func(t *testing.T, attrRepo *mock_domain.MockUserAttributeRepository) {
				attrRepo.EXPECT().CreateAttribute(gomock.Any(), gomock.Any()).
					DoAndReturn(func(_ context.Context, attr *domain.UserAttribute) error {
						assert.Equal(t, "u1", attr.UserID)
						assert.Equal(t, "email", attr.Name)
						assert.Equal(t, "e@example.com", attr.Value)
						assert.Empty(t, attr.ID, "repository assigns the ID")
						attr.ID = "attr-1"
						return nil
					})
			},
		},
		{
			name:     "rejects missing user_id",
			reqMsg:   &ssov1.CreateUserAttributeRequest{Name: "email", Value: "e@example.com"},
			wantErr:  true,
			wantCode: connect.CodeInvalidArgument,
		},
		{
			name:     "rejects missing name",
			reqMsg:   &ssov1.CreateUserAttributeRequest{UserId: "u1", Value: "e@example.com"},
			wantErr:  true,
			wantCode: connect.CodeInvalidArgument,
		},
		{
			name:     "rejects missing value",
			reqMsg:   &ssov1.CreateUserAttributeRequest{UserId: "u1", Name: "email"},
			wantErr:  true,
			wantCode: connect.CodeInvalidArgument,
		},
		{
			name:   "repository error maps to CodeInternal",
			reqMsg: &ssov1.CreateUserAttributeRequest{UserId: "u1", Name: "email", Value: "e@example.com"},
			setup: func(t *testing.T, attrRepo *mock_domain.MockUserAttributeRepository) {
				attrRepo.EXPECT().CreateAttribute(gomock.Any(), gomock.Any()).Return(errors.New("database down"))
			},
			wantErr:  true,
			wantCode: connect.CodeInternal,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			attrRepo := mock_domain.NewMockUserAttributeRepository(ctrl)
			if tt.setup != nil {
				tt.setup(t, attrRepo)
			}
			service := NewUserAttributeServiceServer(attrRepo, mock_domain.NewMockUserAttributeMapperRepository(ctrl))

			resp, err := service.CreateUserAttribute(context.Background(), connect.NewRequest(tt.reqMsg))
			if tt.wantErr {
				require.Error(t, err)
				assert.Equal(t, tt.wantCode, connect.CodeOf(err))
				return
			}
			require.NoError(t, err)
			require.NotNil(t, resp.Msg)
			require.NotNil(t, resp.Msg.UserAttribute)
			assert.Equal(t, "attr-1", resp.Msg.UserAttribute.Id)
			assert.Equal(t, tt.reqMsg.Name, resp.Msg.UserAttribute.Name)
			assert.Equal(t, tt.reqMsg.Value, resp.Msg.UserAttribute.Value)
			assert.Equal(t, tt.reqMsg.UserId, resp.Msg.UserAttribute.UserId)
			assert.Nil(t, resp.Msg.UserAttribute.CreatedAt, "domain.UserAttribute has no timestamps")
			assert.Nil(t, resp.Msg.UserAttribute.UpdatedAt)
		})
	}
}

// TestUserAttributeServiceServer_GetUserAttribute covers the get-by-id path
// including both not-found error flavors handled by isNotFoundError.
func TestUserAttributeServiceServer_GetUserAttribute(t *testing.T) {
	tests := []struct {
		name     string
		reqMsg   *ssov1.GetUserAttributeRequest
		setup    func(t *testing.T, attrRepo *mock_domain.MockUserAttributeRepository)
		wantErr  bool
		wantCode connect.Code
	}{
		{
			name:   "returns attribute by id",
			reqMsg: &ssov1.GetUserAttributeRequest{Id: "attr-1"},
			setup: func(t *testing.T, attrRepo *mock_domain.MockUserAttributeRepository) {
				attrRepo.EXPECT().GetAttributeByID(gomock.Any(), "attr-1").Return(
					&domain.UserAttribute{ID: "attr-1", Name: "email", Value: "e@example.com", UserID: "u1"}, nil)
			},
		},
		{
			name:   "not found maps to CodeNotFound (mongo no documents)",
			reqMsg: &ssov1.GetUserAttributeRequest{Id: "missing"},
			setup: func(t *testing.T, attrRepo *mock_domain.MockUserAttributeRepository) {
				attrRepo.EXPECT().GetAttributeByID(gomock.Any(), "missing").Return(nil, mongo.ErrNoDocuments)
			},
			wantErr:  true,
			wantCode: connect.CodeNotFound,
		},
		{
			name:   "not found maps to CodeNotFound (not found message)",
			reqMsg: &ssov1.GetUserAttributeRequest{Id: "missing"},
			setup: func(t *testing.T, attrRepo *mock_domain.MockUserAttributeRepository) {
				attrRepo.EXPECT().GetAttributeByID(gomock.Any(), "missing").Return(nil, errors.New("user attribute not found"))
			},
			wantErr:  true,
			wantCode: connect.CodeNotFound,
		},
		{
			name:   "repository error maps to CodeInternal",
			reqMsg: &ssov1.GetUserAttributeRequest{Id: "attr-1"},
			setup: func(t *testing.T, attrRepo *mock_domain.MockUserAttributeRepository) {
				attrRepo.EXPECT().GetAttributeByID(gomock.Any(), "attr-1").Return(nil, errors.New("database down"))
			},
			wantErr:  true,
			wantCode: connect.CodeInternal,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			attrRepo := mock_domain.NewMockUserAttributeRepository(ctrl)
			if tt.setup != nil {
				tt.setup(t, attrRepo)
			}
			service := NewUserAttributeServiceServer(attrRepo, mock_domain.NewMockUserAttributeMapperRepository(ctrl))

			resp, err := service.GetUserAttribute(context.Background(), connect.NewRequest(tt.reqMsg))
			if tt.wantErr {
				require.Error(t, err)
				assert.Equal(t, tt.wantCode, connect.CodeOf(err))
				return
			}
			require.NoError(t, err)
			require.NotNil(t, resp.Msg)
			require.NotNil(t, resp.Msg.UserAttribute)
			assert.Equal(t, "attr-1", resp.Msg.UserAttribute.Id)
			assert.Equal(t, "email", resp.Msg.UserAttribute.Name)
			assert.Equal(t, "e@example.com", resp.Msg.UserAttribute.Value)
			assert.Equal(t, "u1", resp.Msg.UserAttribute.UserId)
		})
	}
}

// TestUserAttributeServiceServer_ListUserAttributes covers the user_id branch
// (GetAttributesByUserID vs ListAllAttributes), the in-memory name filter,
// pagination and repo error mapping.
func TestUserAttributeServiceServer_ListUserAttributes(t *testing.T) {
	attr1 := &domain.UserAttribute{ID: "a1", Name: "email", Value: "e@example.com", UserID: "u1"}
	attr2 := &domain.UserAttribute{ID: "a2", Name: "phone", Value: "+123456", UserID: "u2"}

	tests := []struct {
		name     string
		reqMsg   *ssov1.ListUserAttributesRequest
		setup    func(t *testing.T, attrRepo *mock_domain.MockUserAttributeRepository)
		wantIDs  []string
		wantNext string
		wantErr  bool
		wantCode connect.Code
	}{
		{
			name:   "lists all attributes when user_id is empty",
			reqMsg: &ssov1.ListUserAttributesRequest{},
			setup: func(t *testing.T, attrRepo *mock_domain.MockUserAttributeRepository) {
				attrRepo.EXPECT().ListAllAttributes(gomock.Any()).Return([]*domain.UserAttribute{attr1, attr2}, nil)
			},
			wantIDs: []string{"a1", "a2"},
		},
		{
			name:   "lists attributes by user id",
			reqMsg: &ssov1.ListUserAttributesRequest{UserId: "u1"},
			setup: func(t *testing.T, attrRepo *mock_domain.MockUserAttributeRepository) {
				attrRepo.EXPECT().GetAttributesByUserID(gomock.Any(), "u1").Return([]*domain.UserAttribute{attr1}, nil)
			},
			wantIDs: []string{"a1"},
		},
		{
			name:   "filters by name in memory",
			reqMsg: &ssov1.ListUserAttributesRequest{Name: "phone"},
			setup: func(t *testing.T, attrRepo *mock_domain.MockUserAttributeRepository) {
				attrRepo.EXPECT().ListAllAttributes(gomock.Any()).Return([]*domain.UserAttribute{attr1, attr2}, nil)
			},
			wantIDs: []string{"a2"},
		},
		{
			name:   "paginates with page size one",
			reqMsg: &ssov1.ListUserAttributesRequest{PageSize: 1},
			setup: func(t *testing.T, attrRepo *mock_domain.MockUserAttributeRepository) {
				attrRepo.EXPECT().ListAllAttributes(gomock.Any()).Return([]*domain.UserAttribute{attr1, attr2}, nil)
			},
			wantIDs:  []string{"a1"},
			wantNext: "1",
		},
		{
			name:   "repository error maps to CodeInternal",
			reqMsg: &ssov1.ListUserAttributesRequest{},
			setup: func(t *testing.T, attrRepo *mock_domain.MockUserAttributeRepository) {
				attrRepo.EXPECT().ListAllAttributes(gomock.Any()).Return(nil, errors.New("database down"))
			},
			wantErr:  true,
			wantCode: connect.CodeInternal,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			attrRepo := mock_domain.NewMockUserAttributeRepository(ctrl)
			if tt.setup != nil {
				tt.setup(t, attrRepo)
			}
			service := NewUserAttributeServiceServer(attrRepo, mock_domain.NewMockUserAttributeMapperRepository(ctrl))

			resp, err := service.ListUserAttributes(context.Background(), connect.NewRequest(tt.reqMsg))
			if tt.wantErr {
				require.Error(t, err)
				assert.Equal(t, tt.wantCode, connect.CodeOf(err))
				return
			}
			require.NoError(t, err)
			require.NotNil(t, resp.Msg)
			gotIDs := make([]string, len(resp.Msg.UserAttributes))
			for i, a := range resp.Msg.UserAttributes {
				gotIDs[i] = a.Id
			}
			assert.Equal(t, tt.wantIDs, gotIDs)
			assert.Equal(t, tt.wantNext, resp.Msg.NextPageToken)
		})
	}
}

// TestUserAttributeServiceServer_UpdateUserAttribute covers the fetch-modify-
// save flow: partial updates must not zero untouched fields, and both
// validation and not-found paths are asserted.
func TestUserAttributeServiceServer_UpdateUserAttribute(t *testing.T) {
	newTestAttribute := func() *domain.UserAttribute {
		return &domain.UserAttribute{ID: "attr-1", Name: "old name", Value: "old value", UserID: "u1"}
	}

	tests := []struct {
		name      string
		reqMsg    *ssov1.UpdateUserAttributeRequest
		setup     func(t *testing.T, attrRepo *mock_domain.MockUserAttributeRepository)
		wantName  string
		wantValue string
		wantErr   bool
		wantCode  connect.Code
	}{
		{
			name:     "rejects update with no fields",
			reqMsg:   &ssov1.UpdateUserAttributeRequest{Id: "attr-1"},
			wantErr:  true,
			wantCode: connect.CodeInvalidArgument,
		},
		{
			name:   "updates name only preserving value",
			reqMsg: &ssov1.UpdateUserAttributeRequest{Id: "attr-1", Name: ToPtr("new name")},
			setup: func(t *testing.T, attrRepo *mock_domain.MockUserAttributeRepository) {
				attrRepo.EXPECT().GetAttributeByID(gomock.Any(), "attr-1").Return(newTestAttribute(), nil)
				attrRepo.EXPECT().UpdateAttribute(gomock.Any(), gomock.Any()).
					DoAndReturn(func(_ context.Context, attr *domain.UserAttribute) error {
						assert.Equal(t, "attr-1", attr.ID)
						assert.Equal(t, "new name", attr.Name)
						assert.Equal(t, "old value", attr.Value, "value must be preserved when not set")
						assert.Equal(t, "u1", attr.UserID, "user id must be preserved when not set")
						return nil
					})
			},
			wantName:  "new name",
			wantValue: "old value",
		},
		{
			name:   "updates value only preserving name",
			reqMsg: &ssov1.UpdateUserAttributeRequest{Id: "attr-1", Value: ToPtr("new value")},
			setup: func(t *testing.T, attrRepo *mock_domain.MockUserAttributeRepository) {
				attrRepo.EXPECT().GetAttributeByID(gomock.Any(), "attr-1").Return(newTestAttribute(), nil)
				attrRepo.EXPECT().UpdateAttribute(gomock.Any(), gomock.Any()).
					DoAndReturn(func(_ context.Context, attr *domain.UserAttribute) error {
						assert.Equal(t, "old name", attr.Name, "name must be preserved when not set")
						assert.Equal(t, "new value", attr.Value)
						return nil
					})
			},
			wantName:  "old name",
			wantValue: "new value",
		},
		{
			name:   "not found maps to CodeNotFound",
			reqMsg: &ssov1.UpdateUserAttributeRequest{Id: "missing", Name: ToPtr("new name")},
			setup: func(t *testing.T, attrRepo *mock_domain.MockUserAttributeRepository) {
				attrRepo.EXPECT().GetAttributeByID(gomock.Any(), "missing").Return(nil, mongo.ErrNoDocuments)
			},
			wantErr:  true,
			wantCode: connect.CodeNotFound,
		},
		{
			name:   "get repository error maps to CodeInternal",
			reqMsg: &ssov1.UpdateUserAttributeRequest{Id: "attr-1", Name: ToPtr("new name")},
			setup: func(t *testing.T, attrRepo *mock_domain.MockUserAttributeRepository) {
				attrRepo.EXPECT().GetAttributeByID(gomock.Any(), "attr-1").Return(nil, errors.New("database down"))
			},
			wantErr:  true,
			wantCode: connect.CodeInternal,
		},
		{
			name:   "update repository error maps to CodeInternal",
			reqMsg: &ssov1.UpdateUserAttributeRequest{Id: "attr-1", Name: ToPtr("new name")},
			setup: func(t *testing.T, attrRepo *mock_domain.MockUserAttributeRepository) {
				attrRepo.EXPECT().GetAttributeByID(gomock.Any(), "attr-1").Return(newTestAttribute(), nil)
				attrRepo.EXPECT().UpdateAttribute(gomock.Any(), gomock.Any()).Return(errors.New("database down"))
			},
			wantErr:  true,
			wantCode: connect.CodeInternal,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			attrRepo := mock_domain.NewMockUserAttributeRepository(ctrl)
			if tt.setup != nil {
				tt.setup(t, attrRepo)
			}
			service := NewUserAttributeServiceServer(attrRepo, mock_domain.NewMockUserAttributeMapperRepository(ctrl))

			resp, err := service.UpdateUserAttribute(context.Background(), connect.NewRequest(tt.reqMsg))
			if tt.wantErr {
				require.Error(t, err)
				assert.Equal(t, tt.wantCode, connect.CodeOf(err))
				return
			}
			require.NoError(t, err)
			require.NotNil(t, resp.Msg)
			require.NotNil(t, resp.Msg.UserAttribute)
			assert.Equal(t, "attr-1", resp.Msg.UserAttribute.Id)
			assert.Equal(t, tt.wantName, resp.Msg.UserAttribute.Name)
			assert.Equal(t, tt.wantValue, resp.Msg.UserAttribute.Value)
		})
	}
}

// TestUserAttributeServiceServer_DeleteUserAttribute covers the delete path
// with not-found and generic repo error mappings.
func TestUserAttributeServiceServer_DeleteUserAttribute(t *testing.T) {
	tests := []struct {
		name     string
		reqMsg   *ssov1.DeleteUserAttributeRequest
		setup    func(t *testing.T, attrRepo *mock_domain.MockUserAttributeRepository)
		wantErr  bool
		wantCode connect.Code
	}{
		{
			name:   "deletes attribute",
			reqMsg: &ssov1.DeleteUserAttributeRequest{Id: "attr-1"},
			setup: func(t *testing.T, attrRepo *mock_domain.MockUserAttributeRepository) {
				attrRepo.EXPECT().DeleteAttribute(gomock.Any(), "attr-1").Return(nil)
			},
		},
		{
			name:   "not found maps to CodeNotFound",
			reqMsg: &ssov1.DeleteUserAttributeRequest{Id: "missing"},
			setup: func(t *testing.T, attrRepo *mock_domain.MockUserAttributeRepository) {
				attrRepo.EXPECT().DeleteAttribute(gomock.Any(), "missing").Return(mongo.ErrNoDocuments)
			},
			wantErr:  true,
			wantCode: connect.CodeNotFound,
		},
		{
			name:   "repository error maps to CodeInternal",
			reqMsg: &ssov1.DeleteUserAttributeRequest{Id: "attr-1"},
			setup: func(t *testing.T, attrRepo *mock_domain.MockUserAttributeRepository) {
				attrRepo.EXPECT().DeleteAttribute(gomock.Any(), "attr-1").Return(errors.New("database down"))
			},
			wantErr:  true,
			wantCode: connect.CodeInternal,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			attrRepo := mock_domain.NewMockUserAttributeRepository(ctrl)
			if tt.setup != nil {
				tt.setup(t, attrRepo)
			}
			service := NewUserAttributeServiceServer(attrRepo, mock_domain.NewMockUserAttributeMapperRepository(ctrl))

			resp, err := service.DeleteUserAttribute(context.Background(), connect.NewRequest(tt.reqMsg))
			if tt.wantErr {
				require.Error(t, err)
				assert.Equal(t, tt.wantCode, connect.CodeOf(err))
				return
			}
			require.NoError(t, err)
			require.NotNil(t, resp.Msg)
		})
	}
}

// TestUserAttributeServiceServer_DeleteUserAttributesByUserId covers the
// user_id validation and the bulk delete path.
func TestUserAttributeServiceServer_DeleteUserAttributesByUserId(t *testing.T) {
	tests := []struct {
		name     string
		reqMsg   *ssov1.DeleteUserAttributesByUserIdRequest
		setup    func(t *testing.T, attrRepo *mock_domain.MockUserAttributeRepository)
		wantErr  bool
		wantCode connect.Code
	}{
		{
			name:     "rejects empty user_id",
			reqMsg:   &ssov1.DeleteUserAttributesByUserIdRequest{},
			wantErr:  true,
			wantCode: connect.CodeInvalidArgument,
		},
		{
			name:   "deletes all attributes of user",
			reqMsg: &ssov1.DeleteUserAttributesByUserIdRequest{UserId: "u1"},
			setup: func(t *testing.T, attrRepo *mock_domain.MockUserAttributeRepository) {
				attrRepo.EXPECT().DeleteAttributesByUserID(gomock.Any(), "u1").Return(nil)
			},
		},
		{
			name:   "repository error maps to CodeInternal",
			reqMsg: &ssov1.DeleteUserAttributesByUserIdRequest{UserId: "u1"},
			setup: func(t *testing.T, attrRepo *mock_domain.MockUserAttributeRepository) {
				attrRepo.EXPECT().DeleteAttributesByUserID(gomock.Any(), "u1").Return(errors.New("database down"))
			},
			wantErr:  true,
			wantCode: connect.CodeInternal,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			attrRepo := mock_domain.NewMockUserAttributeRepository(ctrl)
			if tt.setup != nil {
				tt.setup(t, attrRepo)
			}
			service := NewUserAttributeServiceServer(attrRepo, mock_domain.NewMockUserAttributeMapperRepository(ctrl))

			resp, err := service.DeleteUserAttributesByUserId(context.Background(), connect.NewRequest(tt.reqMsg))
			if tt.wantErr {
				require.Error(t, err)
				assert.Equal(t, tt.wantCode, connect.CodeOf(err))
				return
			}
			require.NoError(t, err)
			require.NotNil(t, resp.Msg)
		})
	}
}

// TestUserAttributeServiceServer_CreateUserAttributeMapper covers the create
// mapper path: defaults (protocol=openid-connect, multi_valued=false,
// client_id=""), token type round-trips for id_token/access_token/userinfo,
// required-field validation and enum validation.
func TestUserAttributeServiceServer_CreateUserAttributeMapper(t *testing.T) {
	createdAt := time.Date(2026, 7, 31, 10, 0, 0, 0, time.UTC)
	updatedAt := time.Date(2026, 7, 31, 11, 0, 0, 0, time.UTC)

	tests := []struct {
		name            string
		reqMsg          *ssov1.CreateUserAttributeMapperRequest
		setup           func(t *testing.T, mapperRepo *mock_domain.MockUserAttributeMapperRepository)
		wantID          string
		wantTokenType   ssov1.TokenTypeProto
		wantProtocol    ssov1.ProtocolProto
		wantMultiValued bool
		wantClientID    string
		wantTimestamps  bool
		wantErr         bool
		wantCode        connect.Code
	}{
		{
			name: "creates mapper with defaults (id_token)",
			reqMsg: &ssov1.CreateUserAttributeMapperRequest{
				Name: "email mapper", UserAttribute: "email", TokenClaimName: "email_claim",
				TokenType: ssov1.TokenTypeProto_TOKEN_TYPE_ID_TOKEN,
			},
			setup: func(t *testing.T, mapperRepo *mock_domain.MockUserAttributeMapperRepository) {
				mapperRepo.EXPECT().CreateMapper(gomock.Any(), gomock.Any()).
					DoAndReturn(func(_ context.Context, m *domain.UserAttributeMapper) error {
						assert.Equal(t, "email mapper", m.Name)
						assert.Equal(t, "email", m.UserAttribute)
						assert.Equal(t, "email_claim", m.TokenClaimName)
						assert.Equal(t, "id_token", m.TokenType)
						assert.Equal(t, "openid-connect", m.Protocol, "protocol must default to openid-connect")
						assert.False(t, m.MultiValued, "multi_valued must default to false")
						assert.Empty(t, m.ClientID, "client_id must default to empty")
						assert.Empty(t, m.ID, "repository assigns the ID")
						m.ID = "map-1"
						m.CreatedAt = createdAt
						m.UpdatedAt = updatedAt
						return nil
					})
			},
			wantID:          "map-1",
			wantTokenType:   ssov1.TokenTypeProto_TOKEN_TYPE_ID_TOKEN,
			wantProtocol:    ssov1.ProtocolProto_PROTOCOL_OPENID_CONNECT,
			wantMultiValued: false,
			wantClientID:    "",
			wantTimestamps:  true,
		},
		{
			name: "creates mapper with all fields (access_token)",
			reqMsg: &ssov1.CreateUserAttributeMapperRequest{
				Name: "phone mapper", UserAttribute: "phone", TokenClaimName: "phone_claim",
				TokenType:   ssov1.TokenTypeProto_TOKEN_TYPE_ACCESS_TOKEN,
				MultiValued: ToPtr(true),
				Protocol:    ToPtr(ssov1.ProtocolProto_PROTOCOL_OPENID_CONNECT),
				ClientId:    ToPtr("client-1"),
			},
			setup: func(t *testing.T, mapperRepo *mock_domain.MockUserAttributeMapperRepository) {
				mapperRepo.EXPECT().CreateMapper(gomock.Any(), gomock.Any()).
					DoAndReturn(func(_ context.Context, m *domain.UserAttributeMapper) error {
						assert.Equal(t, "access_token", m.TokenType)
						assert.True(t, m.MultiValued)
						assert.Equal(t, "openid-connect", m.Protocol)
						assert.Equal(t, "client-1", m.ClientID)
						m.ID = "map-2"
						return nil
					})
			},
			wantID:          "map-2",
			wantTokenType:   ssov1.TokenTypeProto_TOKEN_TYPE_ACCESS_TOKEN,
			wantProtocol:    ssov1.ProtocolProto_PROTOCOL_OPENID_CONNECT,
			wantMultiValued: true,
			wantClientID:    "client-1",
		},
		{
			name: "creates mapper round-trips userinfo token type",
			reqMsg: &ssov1.CreateUserAttributeMapperRequest{
				Name: "roles mapper", UserAttribute: "roles", TokenClaimName: "roles_claim",
				TokenType: ssov1.TokenTypeProto_TOKEN_TYPE_USERINFO,
			},
			setup: func(t *testing.T, mapperRepo *mock_domain.MockUserAttributeMapperRepository) {
				mapperRepo.EXPECT().CreateMapper(gomock.Any(), gomock.Any()).
					DoAndReturn(func(_ context.Context, m *domain.UserAttributeMapper) error {
						assert.Equal(t, "userinfo", m.TokenType)
						m.ID = "map-3"
						return nil
					})
			},
			wantID:          "map-3",
			wantTokenType:   ssov1.TokenTypeProto_TOKEN_TYPE_USERINFO,
			wantProtocol:    ssov1.ProtocolProto_PROTOCOL_OPENID_CONNECT,
			wantMultiValued: false,
			wantClientID:    "",
		},
		{
			name: "rejects missing name",
			reqMsg: &ssov1.CreateUserAttributeMapperRequest{
				UserAttribute: "email", TokenClaimName: "email_claim",
				TokenType: ssov1.TokenTypeProto_TOKEN_TYPE_ID_TOKEN,
			},
			wantErr:  true,
			wantCode: connect.CodeInvalidArgument,
		},
		{
			name: "rejects missing user_attribute",
			reqMsg: &ssov1.CreateUserAttributeMapperRequest{
				Name: "email mapper", TokenClaimName: "email_claim",
				TokenType: ssov1.TokenTypeProto_TOKEN_TYPE_ID_TOKEN,
			},
			wantErr:  true,
			wantCode: connect.CodeInvalidArgument,
		},
		{
			name: "rejects missing token_claim_name",
			reqMsg: &ssov1.CreateUserAttributeMapperRequest{
				Name: "email mapper", UserAttribute: "email",
				TokenType: ssov1.TokenTypeProto_TOKEN_TYPE_ID_TOKEN,
			},
			wantErr:  true,
			wantCode: connect.CodeInvalidArgument,
		},
		{
			name: "rejects invalid token type",
			reqMsg: &ssov1.CreateUserAttributeMapperRequest{
				Name: "email mapper", UserAttribute: "email", TokenClaimName: "email_claim",
			},
			wantErr:  true,
			wantCode: connect.CodeInvalidArgument,
		},
		{
			name: "rejects invalid protocol",
			reqMsg: &ssov1.CreateUserAttributeMapperRequest{
				Name: "email mapper", UserAttribute: "email", TokenClaimName: "email_claim",
				TokenType: ssov1.TokenTypeProto_TOKEN_TYPE_ID_TOKEN,
				Protocol:  ToPtr(ssov1.ProtocolProto(99)),
			},
			wantErr:  true,
			wantCode: connect.CodeInvalidArgument,
		},
		{
			name: "repository error maps to CodeInternal",
			reqMsg: &ssov1.CreateUserAttributeMapperRequest{
				Name: "email mapper", UserAttribute: "email", TokenClaimName: "email_claim",
				TokenType: ssov1.TokenTypeProto_TOKEN_TYPE_ID_TOKEN,
			},
			setup: func(t *testing.T, mapperRepo *mock_domain.MockUserAttributeMapperRepository) {
				mapperRepo.EXPECT().CreateMapper(gomock.Any(), gomock.Any()).Return(errors.New("database down"))
			},
			wantErr:  true,
			wantCode: connect.CodeInternal,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mapperRepo := mock_domain.NewMockUserAttributeMapperRepository(ctrl)
			if tt.setup != nil {
				tt.setup(t, mapperRepo)
			}
			service := NewUserAttributeServiceServer(mock_domain.NewMockUserAttributeRepository(ctrl), mapperRepo)

			resp, err := service.CreateUserAttributeMapper(context.Background(), connect.NewRequest(tt.reqMsg))
			if tt.wantErr {
				require.Error(t, err)
				assert.Equal(t, tt.wantCode, connect.CodeOf(err))
				return
			}
			require.NoError(t, err)
			require.NotNil(t, resp.Msg)
			require.NotNil(t, resp.Msg.UserAttributeMapper)
			assert.Equal(t, tt.wantID, resp.Msg.UserAttributeMapper.Id)
			assert.Equal(t, tt.wantTokenType, resp.Msg.UserAttributeMapper.TokenType)
			assert.Equal(t, tt.wantProtocol, resp.Msg.UserAttributeMapper.Protocol)
			assert.Equal(t, tt.wantMultiValued, resp.Msg.UserAttributeMapper.MultiValued)
			assert.Equal(t, tt.wantClientID, resp.Msg.UserAttributeMapper.ClientId)
			if tt.wantTimestamps {
				require.NotNil(t, resp.Msg.UserAttributeMapper.CreatedAt)
				require.NotNil(t, resp.Msg.UserAttributeMapper.UpdatedAt)
				assert.Equal(t, timestamppb.New(createdAt), resp.Msg.UserAttributeMapper.CreatedAt)
				assert.Equal(t, timestamppb.New(updatedAt), resp.Msg.UserAttributeMapper.UpdatedAt)
			}
		})
	}
}

// TestUserAttributeServiceServer_GetUserAttributeMapper covers the mapper
// get-by-id path including timestamp conversion and not-found mapping.
func TestUserAttributeServiceServer_GetUserAttributeMapper(t *testing.T) {
	createdAt := time.Date(2026, 7, 31, 10, 0, 0, 0, time.UTC)
	updatedAt := time.Date(2026, 7, 31, 11, 0, 0, 0, time.UTC)

	tests := []struct {
		name     string
		reqMsg   *ssov1.GetUserAttributeMapperRequest
		setup    func(t *testing.T, mapperRepo *mock_domain.MockUserAttributeMapperRepository)
		wantErr  bool
		wantCode connect.Code
	}{
		{
			name:   "returns mapper by id with timestamps",
			reqMsg: &ssov1.GetUserAttributeMapperRequest{Id: "map-1"},
			setup: func(t *testing.T, mapperRepo *mock_domain.MockUserAttributeMapperRepository) {
				mapperRepo.EXPECT().GetMapperByID(gomock.Any(), "map-1").Return(&domain.UserAttributeMapper{
					ID: "map-1", Name: "email mapper", UserAttribute: "email", TokenClaimName: "email_claim",
					TokenType: "access_token", MultiValued: true, Protocol: "openid-connect", ClientID: "client-1",
					CreatedAt: createdAt, UpdatedAt: updatedAt,
				}, nil)
			},
		},
		{
			name:   "not found maps to CodeNotFound",
			reqMsg: &ssov1.GetUserAttributeMapperRequest{Id: "missing"},
			setup: func(t *testing.T, mapperRepo *mock_domain.MockUserAttributeMapperRepository) {
				mapperRepo.EXPECT().GetMapperByID(gomock.Any(), "missing").Return(nil, mongo.ErrNoDocuments)
			},
			wantErr:  true,
			wantCode: connect.CodeNotFound,
		},
		{
			name:   "repository error maps to CodeInternal",
			reqMsg: &ssov1.GetUserAttributeMapperRequest{Id: "map-1"},
			setup: func(t *testing.T, mapperRepo *mock_domain.MockUserAttributeMapperRepository) {
				mapperRepo.EXPECT().GetMapperByID(gomock.Any(), "map-1").Return(nil, errors.New("database down"))
			},
			wantErr:  true,
			wantCode: connect.CodeInternal,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mapperRepo := mock_domain.NewMockUserAttributeMapperRepository(ctrl)
			if tt.setup != nil {
				tt.setup(t, mapperRepo)
			}
			service := NewUserAttributeServiceServer(mock_domain.NewMockUserAttributeRepository(ctrl), mapperRepo)

			resp, err := service.GetUserAttributeMapper(context.Background(), connect.NewRequest(tt.reqMsg))
			if tt.wantErr {
				require.Error(t, err)
				assert.Equal(t, tt.wantCode, connect.CodeOf(err))
				return
			}
			require.NoError(t, err)
			require.NotNil(t, resp.Msg)
			require.NotNil(t, resp.Msg.UserAttributeMapper)
			assert.Equal(t, "map-1", resp.Msg.UserAttributeMapper.Id)
			assert.Equal(t, "email mapper", resp.Msg.UserAttributeMapper.Name)
			assert.Equal(t, "email", resp.Msg.UserAttributeMapper.UserAttribute)
			assert.Equal(t, "email_claim", resp.Msg.UserAttributeMapper.TokenClaimName)
			assert.Equal(t, ssov1.TokenTypeProto_TOKEN_TYPE_ACCESS_TOKEN, resp.Msg.UserAttributeMapper.TokenType)
			assert.True(t, resp.Msg.UserAttributeMapper.MultiValued)
			assert.Equal(t, ssov1.ProtocolProto_PROTOCOL_OPENID_CONNECT, resp.Msg.UserAttributeMapper.Protocol)
			assert.Equal(t, "client-1", resp.Msg.UserAttributeMapper.ClientId)
			assert.Equal(t, timestamppb.New(createdAt), resp.Msg.UserAttributeMapper.CreatedAt)
			assert.Equal(t, timestamppb.New(updatedAt), resp.Msg.UserAttributeMapper.UpdatedAt)
		})
	}
}

// TestUserAttributeServiceServer_ListUserAttributeMappers covers all four
// repository branches (ListAllMappers, GetMappersByTokenType,
// GetClientMappers, GetMappersForClient), the in-memory user_attribute filter,
// pagination and error mapping.
func TestUserAttributeServiceServer_ListUserAttributeMappers(t *testing.T) {
	createdAt := time.Date(2026, 7, 31, 10, 0, 0, 0, time.UTC)
	updatedAt := time.Date(2026, 7, 31, 11, 0, 0, 0, time.UTC)
	m1 := &domain.UserAttributeMapper{
		ID: "map-1", Name: "email mapper", UserAttribute: "email", TokenClaimName: "email_claim",
		TokenType: "id_token", MultiValued: true, Protocol: "openid-connect", ClientID: "client-1",
		CreatedAt: createdAt, UpdatedAt: updatedAt,
	}
	m2 := &domain.UserAttributeMapper{
		ID: "map-2", Name: "phone mapper", UserAttribute: "phone", TokenClaimName: "phone_claim",
		TokenType: "access_token", MultiValued: false, Protocol: "openid-connect", ClientID: "client-2",
		CreatedAt: createdAt, UpdatedAt: updatedAt,
	}

	tests := []struct {
		name     string
		reqMsg   *ssov1.ListUserAttributeMappersRequest
		setup    func(t *testing.T, mapperRepo *mock_domain.MockUserAttributeMapperRepository)
		check    func(t *testing.T, resp *ssov1.ListUserAttributeMappersResponse)
		wantIDs  []string
		wantNext string
		wantErr  bool
		wantCode connect.Code
	}{
		{
			name:   "lists all mappers when no filters",
			reqMsg: &ssov1.ListUserAttributeMappersRequest{},
			setup: func(t *testing.T, mapperRepo *mock_domain.MockUserAttributeMapperRepository) {
				mapperRepo.EXPECT().ListAllMappers(gomock.Any()).Return([]*domain.UserAttributeMapper{m1, m2}, nil)
			},
			check: func(t *testing.T, resp *ssov1.ListUserAttributeMappersResponse) {
				got := resp.UserAttributeMappers[0]
				assert.Equal(t, ssov1.TokenTypeProto_TOKEN_TYPE_ID_TOKEN, got.TokenType)
				assert.Equal(t, ssov1.ProtocolProto_PROTOCOL_OPENID_CONNECT, got.Protocol)
				assert.True(t, got.MultiValued)
				assert.Equal(t, "client-1", got.ClientId)
				assert.Equal(t, timestamppb.New(createdAt), got.CreatedAt)
				assert.Equal(t, timestamppb.New(updatedAt), got.UpdatedAt)
			},
			wantIDs: []string{"map-1", "map-2"},
		},
		{
			name:   "filters by token type",
			reqMsg: &ssov1.ListUserAttributeMappersRequest{TokenType: ssov1.TokenTypeProto_TOKEN_TYPE_ACCESS_TOKEN},
			setup: func(t *testing.T, mapperRepo *mock_domain.MockUserAttributeMapperRepository) {
				mapperRepo.EXPECT().GetMappersByTokenType(gomock.Any(), "access_token").Return([]*domain.UserAttributeMapper{m2}, nil)
			},
			wantIDs: []string{"map-2"},
		},
		{
			name:   "filters by client id",
			reqMsg: &ssov1.ListUserAttributeMappersRequest{ClientId: "client-1"},
			setup: func(t *testing.T, mapperRepo *mock_domain.MockUserAttributeMapperRepository) {
				mapperRepo.EXPECT().GetClientMappers(gomock.Any(), "client-1").Return([]*domain.UserAttributeMapper{m1}, nil)
			},
			wantIDs: []string{"map-1"},
		},
		{
			name:   "filters by token type and client id",
			reqMsg: &ssov1.ListUserAttributeMappersRequest{TokenType: ssov1.TokenTypeProto_TOKEN_TYPE_ID_TOKEN, ClientId: "client-1"},
			setup: func(t *testing.T, mapperRepo *mock_domain.MockUserAttributeMapperRepository) {
				mapperRepo.EXPECT().GetMappersForClient(gomock.Any(), "client-1", "id_token").Return([]*domain.UserAttributeMapper{m1}, nil)
			},
			wantIDs: []string{"map-1"},
		},
		{
			name:   "filters by user attribute in memory",
			reqMsg: &ssov1.ListUserAttributeMappersRequest{UserAttribute: "phone"},
			setup: func(t *testing.T, mapperRepo *mock_domain.MockUserAttributeMapperRepository) {
				mapperRepo.EXPECT().ListAllMappers(gomock.Any()).Return([]*domain.UserAttributeMapper{m1, m2}, nil)
			},
			wantIDs: []string{"map-2"},
		},
		{
			name:   "paginates with page size one",
			reqMsg: &ssov1.ListUserAttributeMappersRequest{PageSize: 1},
			setup: func(t *testing.T, mapperRepo *mock_domain.MockUserAttributeMapperRepository) {
				mapperRepo.EXPECT().ListAllMappers(gomock.Any()).Return([]*domain.UserAttributeMapper{m1, m2}, nil)
			},
			wantIDs:  []string{"map-1"},
			wantNext: "1",
		},
		{
			name:     "rejects invalid token type filter",
			reqMsg:   &ssov1.ListUserAttributeMappersRequest{TokenType: ssov1.TokenTypeProto(99)},
			wantErr:  true,
			wantCode: connect.CodeInvalidArgument,
		},
		{
			name:   "repository error maps to CodeInternal",
			reqMsg: &ssov1.ListUserAttributeMappersRequest{},
			setup: func(t *testing.T, mapperRepo *mock_domain.MockUserAttributeMapperRepository) {
				mapperRepo.EXPECT().ListAllMappers(gomock.Any()).Return(nil, errors.New("database down"))
			},
			wantErr:  true,
			wantCode: connect.CodeInternal,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mapperRepo := mock_domain.NewMockUserAttributeMapperRepository(ctrl)
			if tt.setup != nil {
				tt.setup(t, mapperRepo)
			}
			service := NewUserAttributeServiceServer(mock_domain.NewMockUserAttributeRepository(ctrl), mapperRepo)

			resp, err := service.ListUserAttributeMappers(context.Background(), connect.NewRequest(tt.reqMsg))
			if tt.wantErr {
				require.Error(t, err)
				assert.Equal(t, tt.wantCode, connect.CodeOf(err))
				return
			}
			require.NoError(t, err)
			require.NotNil(t, resp.Msg)
			gotIDs := make([]string, len(resp.Msg.UserAttributeMappers))
			for i, m := range resp.Msg.UserAttributeMappers {
				gotIDs[i] = m.Id
			}
			assert.Equal(t, tt.wantIDs, gotIDs)
			assert.Equal(t, tt.wantNext, resp.Msg.NextPageToken)
			if tt.check != nil {
				tt.check(t, resp.Msg)
			}
		})
	}
}

// TestUserAttributeServiceServer_UpdateUserAttributeMapper covers the mapper
// fetch-modify-save flow: partial updates preserve untouched fields, enum
// conversions are validated, and not-found maps to CodeNotFound.
func TestUserAttributeServiceServer_UpdateUserAttributeMapper(t *testing.T) {
	createdAt := time.Date(2026, 7, 31, 10, 0, 0, 0, time.UTC)
	updatedAt := time.Date(2026, 7, 31, 11, 0, 0, 0, time.UTC)
	newTestMapper := func() *domain.UserAttributeMapper {
		return &domain.UserAttributeMapper{
			ID: "map-1", Name: "old name", UserAttribute: "email", TokenClaimName: "email_claim",
			TokenType: "access_token", MultiValued: true, Protocol: "openid-connect", ClientID: "client-1",
			CreatedAt: createdAt, UpdatedAt: updatedAt,
		}
	}

	tests := []struct {
		name            string
		reqMsg          *ssov1.UpdateUserAttributeMapperRequest
		setup           func(t *testing.T, mapperRepo *mock_domain.MockUserAttributeMapperRepository)
		wantName        string
		wantTokenType   ssov1.TokenTypeProto
		wantProtocol    ssov1.ProtocolProto
		wantMultiValued bool
		wantClientID    string
		wantErr         bool
		wantCode        connect.Code
	}{
		{
			name:     "rejects update with no fields",
			reqMsg:   &ssov1.UpdateUserAttributeMapperRequest{Id: "map-1"},
			wantErr:  true,
			wantCode: connect.CodeInvalidArgument,
		},
		{
			name:   "updates name only preserving other fields",
			reqMsg: &ssov1.UpdateUserAttributeMapperRequest{Id: "map-1", Name: ToPtr("new name")},
			setup: func(t *testing.T, mapperRepo *mock_domain.MockUserAttributeMapperRepository) {
				mapperRepo.EXPECT().GetMapperByID(gomock.Any(), "map-1").Return(newTestMapper(), nil)
				mapperRepo.EXPECT().UpdateMapper(gomock.Any(), gomock.Any()).
					DoAndReturn(func(_ context.Context, m *domain.UserAttributeMapper) error {
						assert.Equal(t, "map-1", m.ID)
						assert.Equal(t, "new name", m.Name)
						assert.Equal(t, "email", m.UserAttribute, "user_attribute must be preserved")
						assert.Equal(t, "email_claim", m.TokenClaimName, "token_claim_name must be preserved")
						assert.Equal(t, "access_token", m.TokenType, "token_type must be preserved")
						assert.True(t, m.MultiValued, "multi_valued must be preserved")
						assert.Equal(t, "openid-connect", m.Protocol, "protocol must be preserved")
						assert.Equal(t, "client-1", m.ClientID, "client_id must be preserved")
						return nil
					})
			},
			wantName:        "new name",
			wantTokenType:   ssov1.TokenTypeProto_TOKEN_TYPE_ACCESS_TOKEN,
			wantProtocol:    ssov1.ProtocolProto_PROTOCOL_OPENID_CONNECT,
			wantMultiValued: true,
			wantClientID:    "client-1",
		},
		{
			name:   "updates token type",
			reqMsg: &ssov1.UpdateUserAttributeMapperRequest{Id: "map-1", TokenType: ToPtr(ssov1.TokenTypeProto_TOKEN_TYPE_ID_TOKEN)},
			setup: func(t *testing.T, mapperRepo *mock_domain.MockUserAttributeMapperRepository) {
				mapperRepo.EXPECT().GetMapperByID(gomock.Any(), "map-1").Return(newTestMapper(), nil)
				mapperRepo.EXPECT().UpdateMapper(gomock.Any(), gomock.Any()).
					DoAndReturn(func(_ context.Context, m *domain.UserAttributeMapper) error {
						assert.Equal(t, "id_token", m.TokenType)
						assert.Equal(t, "old name", m.Name, "name must be preserved")
						return nil
					})
			},
			wantName:        "old name",
			wantTokenType:   ssov1.TokenTypeProto_TOKEN_TYPE_ID_TOKEN,
			wantProtocol:    ssov1.ProtocolProto_PROTOCOL_OPENID_CONNECT,
			wantMultiValued: true,
			wantClientID:    "client-1",
		},
		{
			name:   "updates multi_valued and client_id",
			reqMsg: &ssov1.UpdateUserAttributeMapperRequest{Id: "map-1", MultiValued: ToPtr(false), ClientId: ToPtr("client-2")},
			setup: func(t *testing.T, mapperRepo *mock_domain.MockUserAttributeMapperRepository) {
				mapperRepo.EXPECT().GetMapperByID(gomock.Any(), "map-1").Return(newTestMapper(), nil)
				mapperRepo.EXPECT().UpdateMapper(gomock.Any(), gomock.Any()).
					DoAndReturn(func(_ context.Context, m *domain.UserAttributeMapper) error {
						assert.False(t, m.MultiValued)
						assert.Equal(t, "client-2", m.ClientID)
						assert.Equal(t, "access_token", m.TokenType, "token_type must be preserved")
						return nil
					})
			},
			wantName:        "old name",
			wantTokenType:   ssov1.TokenTypeProto_TOKEN_TYPE_ACCESS_TOKEN,
			wantProtocol:    ssov1.ProtocolProto_PROTOCOL_OPENID_CONNECT,
			wantMultiValued: false,
			wantClientID:    "client-2",
		},
		{
			name:   "rejects invalid token type",
			reqMsg: &ssov1.UpdateUserAttributeMapperRequest{Id: "map-1", TokenType: ToPtr(ssov1.TokenTypeProto(99))},
			setup: func(t *testing.T, mapperRepo *mock_domain.MockUserAttributeMapperRepository) {
				// The service fetches the mapper before converting the enum.
				mapperRepo.EXPECT().GetMapperByID(gomock.Any(), "map-1").Return(newTestMapper(), nil)
			},
			wantErr:  true,
			wantCode: connect.CodeInvalidArgument,
		},
		{
			name:   "rejects invalid protocol",
			reqMsg: &ssov1.UpdateUserAttributeMapperRequest{Id: "map-1", Protocol: ToPtr(ssov1.ProtocolProto(99))},
			setup: func(t *testing.T, mapperRepo *mock_domain.MockUserAttributeMapperRepository) {
				// The service fetches the mapper before converting the enum.
				mapperRepo.EXPECT().GetMapperByID(gomock.Any(), "map-1").Return(newTestMapper(), nil)
			},
			wantErr:  true,
			wantCode: connect.CodeInvalidArgument,
		},
		{
			name:   "not found maps to CodeNotFound",
			reqMsg: &ssov1.UpdateUserAttributeMapperRequest{Id: "missing", Name: ToPtr("new name")},
			setup: func(t *testing.T, mapperRepo *mock_domain.MockUserAttributeMapperRepository) {
				mapperRepo.EXPECT().GetMapperByID(gomock.Any(), "missing").Return(nil, mongo.ErrNoDocuments)
			},
			wantErr:  true,
			wantCode: connect.CodeNotFound,
		},
		{
			name:   "repository error maps to CodeInternal",
			reqMsg: &ssov1.UpdateUserAttributeMapperRequest{Id: "map-1", Name: ToPtr("new name")},
			setup: func(t *testing.T, mapperRepo *mock_domain.MockUserAttributeMapperRepository) {
				mapperRepo.EXPECT().GetMapperByID(gomock.Any(), "map-1").Return(newTestMapper(), nil)
				mapperRepo.EXPECT().UpdateMapper(gomock.Any(), gomock.Any()).Return(errors.New("database down"))
			},
			wantErr:  true,
			wantCode: connect.CodeInternal,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mapperRepo := mock_domain.NewMockUserAttributeMapperRepository(ctrl)
			if tt.setup != nil {
				tt.setup(t, mapperRepo)
			}
			service := NewUserAttributeServiceServer(mock_domain.NewMockUserAttributeRepository(ctrl), mapperRepo)

			resp, err := service.UpdateUserAttributeMapper(context.Background(), connect.NewRequest(tt.reqMsg))
			if tt.wantErr {
				require.Error(t, err)
				assert.Equal(t, tt.wantCode, connect.CodeOf(err))
				return
			}
			require.NoError(t, err)
			require.NotNil(t, resp.Msg)
			require.NotNil(t, resp.Msg.UserAttributeMapper)
			assert.Equal(t, "map-1", resp.Msg.UserAttributeMapper.Id)
			assert.Equal(t, tt.wantName, resp.Msg.UserAttributeMapper.Name)
			assert.Equal(t, tt.wantTokenType, resp.Msg.UserAttributeMapper.TokenType)
			assert.Equal(t, tt.wantProtocol, resp.Msg.UserAttributeMapper.Protocol)
			assert.Equal(t, tt.wantMultiValued, resp.Msg.UserAttributeMapper.MultiValued)
			assert.Equal(t, tt.wantClientID, resp.Msg.UserAttributeMapper.ClientId)
		})
	}
}

// TestUserAttributeServiceServer_DeleteUserAttributeMapper covers the mapper
// delete path with not-found and generic repo error mappings.
func TestUserAttributeServiceServer_DeleteUserAttributeMapper(t *testing.T) {
	tests := []struct {
		name     string
		reqMsg   *ssov1.DeleteUserAttributeMapperRequest
		setup    func(t *testing.T, mapperRepo *mock_domain.MockUserAttributeMapperRepository)
		wantErr  bool
		wantCode connect.Code
	}{
		{
			name:   "deletes mapper",
			reqMsg: &ssov1.DeleteUserAttributeMapperRequest{Id: "map-1"},
			setup: func(t *testing.T, mapperRepo *mock_domain.MockUserAttributeMapperRepository) {
				mapperRepo.EXPECT().DeleteMapper(gomock.Any(), "map-1").Return(nil)
			},
		},
		{
			name:   "not found maps to CodeNotFound",
			reqMsg: &ssov1.DeleteUserAttributeMapperRequest{Id: "missing"},
			setup: func(t *testing.T, mapperRepo *mock_domain.MockUserAttributeMapperRepository) {
				mapperRepo.EXPECT().DeleteMapper(gomock.Any(), "missing").Return(mongo.ErrNoDocuments)
			},
			wantErr:  true,
			wantCode: connect.CodeNotFound,
		},
		{
			name:   "repository error maps to CodeInternal",
			reqMsg: &ssov1.DeleteUserAttributeMapperRequest{Id: "map-1"},
			setup: func(t *testing.T, mapperRepo *mock_domain.MockUserAttributeMapperRepository) {
				mapperRepo.EXPECT().DeleteMapper(gomock.Any(), "map-1").Return(errors.New("database down"))
			},
			wantErr:  true,
			wantCode: connect.CodeInternal,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mapperRepo := mock_domain.NewMockUserAttributeMapperRepository(ctrl)
			if tt.setup != nil {
				tt.setup(t, mapperRepo)
			}
			service := NewUserAttributeServiceServer(mock_domain.NewMockUserAttributeRepository(ctrl), mapperRepo)

			resp, err := service.DeleteUserAttributeMapper(context.Background(), connect.NewRequest(tt.reqMsg))
			if tt.wantErr {
				require.Error(t, err)
				assert.Equal(t, tt.wantCode, connect.CodeOf(err))
				return
			}
			require.NoError(t, err)
			require.NotNil(t, resp.Msg)
		})
	}
}
