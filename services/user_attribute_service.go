package services

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"connectrpc.com/connect"
	"github.com/pilab-dev/shadow-sso/domain"
	ssov1 "github.com/pilab-dev/shadow-sso/gen/proto/sso/v1"
	"github.com/pilab-dev/shadow-sso/gen/proto/sso/v1/ssov1connect"
	"github.com/pilab-dev/shadow-sso/internal/telemetry"
	"github.com/rs/zerolog/log"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const userAttributeServiceTracerName = "user-attribute-service"

// Canonical string values stored in the domain layer. They MUST match the
// values the token service passes to the mapper repository at runtime
// (services/token_service.go ApplyTokenMappers + docs/user_attributes.md).
const (
	userAttributeTokenTypeIDToken     = "id_token"
	userAttributeTokenTypeAccessToken = "access_token"
	userAttributeTokenTypeUserInfo    = "userinfo"
	userAttributeProtocolOIDC         = "openid-connect"

	userAttributeDefaultPageSize = 50
	userAttributeMaxPageSize     = 100
)

// UserAttributeServiceServer implements both the ssov1.UserAttributeService
// and ssov1.UserAttributeMapperService handlers, backed by the user attribute
// and user attribute mapper repositories.
type UserAttributeServiceServer struct {
	ssov1connect.UnimplementedUserAttributeServiceHandler
	ssov1connect.UnimplementedUserAttributeMapperServiceHandler

	attrRepo   domain.UserAttributeRepository
	mapperRepo domain.UserAttributeMapperRepository
}

// NewUserAttributeServiceServer creates a new UserAttributeServiceServer.
func NewUserAttributeServiceServer(attrRepo domain.UserAttributeRepository, mapperRepo domain.UserAttributeMapperRepository) *UserAttributeServiceServer {
	return &UserAttributeServiceServer{
		attrRepo:   attrRepo,
		mapperRepo: mapperRepo,
	}
}

// Ensure UserAttributeServiceServer satisfies both handler interfaces.
var (
	_ ssov1connect.UserAttributeServiceHandler       = (*UserAttributeServiceServer)(nil)
	_ ssov1connect.UserAttributeMapperServiceHandler = (*UserAttributeServiceServer)(nil)
)

// CreateUserAttribute creates a new user attribute.
func (s *UserAttributeServiceServer) CreateUserAttribute(ctx context.Context, req *connect.Request[ssov1.CreateUserAttributeRequest]) (*connect.Response[ssov1.CreateUserAttributeResponse], error) {
	ctx, span := telemetry.StartSpan(ctx, userAttributeServiceTracerName, "CreateUserAttribute",
		attribute.String("user.id", req.Msg.UserId),
		attribute.String("attribute.name", req.Msg.Name),
	)
	defer span.End()

	attr := fromCreateUserAttributeRequest(req.Msg)
	if attr.UserID == "" || attr.Name == "" || attr.Value == "" {
		err := errors.New("user_id, name and value are required")
		telemetry.RecordSpanError(span, err, "invalid create user attribute request")
		span.SetStatus(codes.Error, "invalid create user attribute request")
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	if err := s.attrRepo.CreateAttribute(ctx, attr); err != nil {
		telemetry.RecordSpanError(span, err, "failed to create user attribute in repository")
		span.SetStatus(codes.Error, "failed to create user attribute")
		log.Ctx(ctx).Error().Err(err).Str("userID", attr.UserID).Str("attributeName", attr.Name).Msg("Failed to create user attribute in repository")
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to create user attribute"))
	}

	log.Ctx(ctx).Info().Str("attributeID", attr.ID).Str("userID", attr.UserID).Msg("User attribute created successfully")
	return connect.NewResponse(&ssov1.CreateUserAttributeResponse{UserAttribute: toUserAttributeProto(attr)}), nil
}

// GetUserAttribute retrieves a user attribute by its ID.
func (s *UserAttributeServiceServer) GetUserAttribute(ctx context.Context, req *connect.Request[ssov1.GetUserAttributeRequest]) (*connect.Response[ssov1.GetUserAttributeResponse], error) {
	ctx, span := telemetry.StartSpan(ctx, userAttributeServiceTracerName, "GetUserAttribute", attribute.String("attribute.id", req.Msg.Id))
	defer span.End()

	dbAttr, err := s.attrRepo.GetAttributeByID(ctx, req.Msg.Id)
	if err != nil {
		telemetry.RecordSpanError(span, err, "failed to get user attribute from repository")
		span.SetStatus(codes.Error, "failed to retrieve user attribute")
		if isNotFoundError(err) {
			log.Ctx(ctx).Warn().Err(err).Str("attributeID", req.Msg.Id).Msg("User attribute not found")
			return nil, connect.NewError(connect.CodeNotFound, errors.New("user attribute not found"))
		}
		log.Ctx(ctx).Error().Err(err).Str("attributeID", req.Msg.Id).Msg("Failed to get user attribute from repository")
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to retrieve user attribute"))
	}
	return connect.NewResponse(&ssov1.GetUserAttributeResponse{UserAttribute: toUserAttributeProto(dbAttr)}), nil
}

// ListUserAttributes lists user attributes with optional filters and pagination.
func (s *UserAttributeServiceServer) ListUserAttributes(ctx context.Context, req *connect.Request[ssov1.ListUserAttributesRequest]) (*connect.Response[ssov1.ListUserAttributesResponse], error) {
	ctx, span := telemetry.StartSpan(ctx, userAttributeServiceTracerName, "ListUserAttributes",
		attribute.String("user.id", req.Msg.UserId),
		attribute.String("attribute.name", req.Msg.Name),
	)
	defer span.End()

	// The name filter is applied in memory below.
	var (
		dbAttrs []*domain.UserAttribute
		err     error
	)
	if req.Msg.UserId != "" {
		dbAttrs, err = s.attrRepo.GetAttributesByUserID(ctx, req.Msg.UserId)
	} else {
		dbAttrs, err = s.attrRepo.ListAllAttributes(ctx)
	}
	if err != nil {
		telemetry.RecordSpanError(span, err, "repository error listing user attributes")
		span.SetStatus(codes.Error, "failed to list user attributes")
		log.Ctx(ctx).Error().Err(err).Str("userID", req.Msg.UserId).Msg("ListUserAttributes: repository error")
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to list user attributes: %w", err))
	}

	filtered := make([]*domain.UserAttribute, 0, len(dbAttrs))
	for _, a := range dbAttrs {
		if req.Msg.Name != "" && a.Name != req.Msg.Name {
			continue
		}
		filtered = append(filtered, a)
	}

	pageSize := normalizePageSize(req.Msg.PageSize)
	offset := pageOffsetFromToken(req.Msg.PageToken)
	page, nextToken := paginate(filtered, offset, pageSize)

	protos := make([]*ssov1.UserAttribute, len(page))
	for i, a := range page {
		protos[i] = toUserAttributeProto(a)
	}

	return connect.NewResponse(&ssov1.ListUserAttributesResponse{
		UserAttributes: protos,
		NextPageToken:  nextToken,
	}), nil
}

// UpdateUserAttribute updates an existing user attribute.
func (s *UserAttributeServiceServer) UpdateUserAttribute(ctx context.Context, req *connect.Request[ssov1.UpdateUserAttributeRequest]) (*connect.Response[ssov1.UpdateUserAttributeResponse], error) {
	ctx, span := telemetry.StartSpan(ctx, userAttributeServiceTracerName, "UpdateUserAttribute", attribute.String("attribute.id", req.Msg.Id))
	defer span.End()

	if req.Msg.Name == nil && req.Msg.Value == nil {
		err := errors.New("at least one of name or value must be provided")
		telemetry.RecordSpanError(span, err, "invalid update user attribute request")
		span.SetStatus(codes.Error, "invalid update user attribute request")
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	dbAttr, err := s.attrRepo.GetAttributeByID(ctx, req.Msg.Id)
	if err != nil {
		telemetry.RecordSpanError(span, err, "failed to retrieve user attribute for update")
		span.SetStatus(codes.Error, "user attribute not found for update")
		if isNotFoundError(err) {
			log.Ctx(ctx).Warn().Err(err).Str("attributeID", req.Msg.Id).Msg("User attribute not found for update")
			return nil, connect.NewError(connect.CodeNotFound, errors.New("user attribute not found for update"))
		}
		log.Ctx(ctx).Error().Err(err).Str("attributeID", req.Msg.Id).Msg("Failed to retrieve user attribute for update")
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to retrieve user attribute for update"))
	}

	if req.Msg.Name != nil {
		dbAttr.Name = *req.Msg.Name
	}
	if req.Msg.Value != nil {
		dbAttr.Value = *req.Msg.Value
	}

	if err := s.attrRepo.UpdateAttribute(ctx, dbAttr); err != nil {
		telemetry.RecordSpanError(span, err, "failed to update user attribute in repository")
		span.SetStatus(codes.Error, "failed to update user attribute")
		log.Ctx(ctx).Error().Err(err).Str("attributeID", dbAttr.ID).Msg("Failed to update user attribute in repository")
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to update user attribute"))
	}

	return connect.NewResponse(&ssov1.UpdateUserAttributeResponse{UserAttribute: toUserAttributeProto(dbAttr)}), nil
}

// DeleteUserAttribute deletes a user attribute by its ID.
func (s *UserAttributeServiceServer) DeleteUserAttribute(ctx context.Context, req *connect.Request[ssov1.DeleteUserAttributeRequest]) (*connect.Response[emptypb.Empty], error) {
	ctx, span := telemetry.StartSpan(ctx, userAttributeServiceTracerName, "DeleteUserAttribute", attribute.String("attribute.id", req.Msg.Id))
	defer span.End()

	if err := s.attrRepo.DeleteAttribute(ctx, req.Msg.Id); err != nil {
		telemetry.RecordSpanError(span, err, "failed to delete user attribute from repository")
		span.SetStatus(codes.Error, "failed to delete user attribute")
		if isNotFoundError(err) {
			log.Ctx(ctx).Warn().Err(err).Str("attributeID", req.Msg.Id).Msg("User attribute not found for deletion")
			return nil, connect.NewError(connect.CodeNotFound, errors.New("user attribute not found for deletion"))
		}
		log.Ctx(ctx).Error().Err(err).Str("attributeID", req.Msg.Id).Msg("Failed to delete user attribute from repository")
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to delete user attribute"))
	}
	log.Ctx(ctx).Info().Str("attributeID", req.Msg.Id).Msg("User attribute deleted successfully")
	return connect.NewResponse(&emptypb.Empty{}), nil
}

// DeleteUserAttributesByUserId deletes all user attributes belonging to a user.
func (s *UserAttributeServiceServer) DeleteUserAttributesByUserId(ctx context.Context, req *connect.Request[ssov1.DeleteUserAttributesByUserIdRequest]) (*connect.Response[emptypb.Empty], error) {
	ctx, span := telemetry.StartSpan(ctx, userAttributeServiceTracerName, "DeleteUserAttributesByUserId", attribute.String("user.id", req.Msg.UserId))
	defer span.End()

	if req.Msg.UserId == "" {
		err := errors.New("user_id is required")
		telemetry.RecordSpanError(span, err, "invalid delete user attributes request")
		span.SetStatus(codes.Error, "invalid delete user attributes request")
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	if err := s.attrRepo.DeleteAttributesByUserID(ctx, req.Msg.UserId); err != nil {
		telemetry.RecordSpanError(span, err, "failed to delete user attributes from repository")
		span.SetStatus(codes.Error, "failed to delete user attributes")
		log.Ctx(ctx).Error().Err(err).Str("userID", req.Msg.UserId).Msg("Failed to delete user attributes from repository")
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to delete user attributes"))
	}
	log.Ctx(ctx).Info().Str("userID", req.Msg.UserId).Msg("User attributes deleted successfully")
	return connect.NewResponse(&emptypb.Empty{}), nil
}

// CreateUserAttributeMapper creates a new user attribute token mapper.
func (s *UserAttributeServiceServer) CreateUserAttributeMapper(ctx context.Context, req *connect.Request[ssov1.CreateUserAttributeMapperRequest]) (*connect.Response[ssov1.CreateUserAttributeMapperResponse], error) {
	ctx, span := telemetry.StartSpan(ctx, userAttributeServiceTracerName, "CreateUserAttributeMapper",
		attribute.String("mapper.name", req.Msg.Name),
		attribute.String("token.type", req.Msg.TokenType.String()),
	)
	defer span.End()

	mapper, err := fromCreateUserAttributeMapperRequest(req.Msg)
	if err != nil {
		telemetry.RecordSpanError(span, err, "invalid create user attribute mapper request")
		span.SetStatus(codes.Error, "invalid create user attribute mapper request")
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	if err := s.mapperRepo.CreateMapper(ctx, mapper); err != nil {
		telemetry.RecordSpanError(span, err, "failed to create user attribute mapper in repository")
		span.SetStatus(codes.Error, "failed to create user attribute mapper")
		log.Ctx(ctx).Error().Err(err).Str("mapperName", mapper.Name).Msg("Failed to create user attribute mapper in repository")
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to create user attribute mapper"))
	}

	log.Ctx(ctx).Info().Str("mapperID", mapper.ID).Str("mapperName", mapper.Name).Msg("User attribute mapper created successfully")
	return connect.NewResponse(&ssov1.CreateUserAttributeMapperResponse{UserAttributeMapper: toUserAttributeMapperProto(mapper)}), nil
}

// GetUserAttributeMapper retrieves a user attribute mapper by its ID.
func (s *UserAttributeServiceServer) GetUserAttributeMapper(ctx context.Context, req *connect.Request[ssov1.GetUserAttributeMapperRequest]) (*connect.Response[ssov1.GetUserAttributeMapperResponse], error) {
	ctx, span := telemetry.StartSpan(ctx, userAttributeServiceTracerName, "GetUserAttributeMapper", attribute.String("mapper.id", req.Msg.Id))
	defer span.End()

	dbMapper, err := s.mapperRepo.GetMapperByID(ctx, req.Msg.Id)
	if err != nil {
		telemetry.RecordSpanError(span, err, "failed to get user attribute mapper from repository")
		span.SetStatus(codes.Error, "failed to retrieve user attribute mapper")
		if isNotFoundError(err) {
			log.Ctx(ctx).Warn().Err(err).Str("mapperID", req.Msg.Id).Msg("User attribute mapper not found")
			return nil, connect.NewError(connect.CodeNotFound, errors.New("user attribute mapper not found"))
		}
		log.Ctx(ctx).Error().Err(err).Str("mapperID", req.Msg.Id).Msg("Failed to get user attribute mapper from repository")
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to retrieve user attribute mapper"))
	}
	return connect.NewResponse(&ssov1.GetUserAttributeMapperResponse{UserAttributeMapper: toUserAttributeMapperProto(dbMapper)}), nil
}

// ListUserAttributeMappers lists user attribute mappers with optional filters
// and pagination.
func (s *UserAttributeServiceServer) ListUserAttributeMappers(ctx context.Context, req *connect.Request[ssov1.ListUserAttributeMappersRequest]) (*connect.Response[ssov1.ListUserAttributeMappersResponse], error) {
	ctx, span := telemetry.StartSpan(ctx, userAttributeServiceTracerName, "ListUserAttributeMappers",
		attribute.String("token.type", req.Msg.TokenType.String()),
		attribute.String("client.id", req.Msg.ClientId),
		attribute.String("user.attribute", req.Msg.UserAttribute),
	)
	defer span.End()

	var (
		dbMappers []*domain.UserAttributeMapper
		err       error
	)
	switch {
	case req.Msg.TokenType != ssov1.TokenTypeProto_TOKEN_TYPE_UNSPECIFIED && req.Msg.ClientId != "":
		tokenType, convErr := fromTokenTypeProto(req.Msg.TokenType)
		if convErr != nil {
			telemetry.RecordSpanError(span, convErr, "invalid token type filter")
			span.SetStatus(codes.Error, "invalid token type filter")
			return nil, connect.NewError(connect.CodeInvalidArgument, convErr)
		}
		dbMappers, err = s.mapperRepo.GetMappersForClient(ctx, req.Msg.ClientId, tokenType)
	case req.Msg.TokenType != ssov1.TokenTypeProto_TOKEN_TYPE_UNSPECIFIED:
		tokenType, convErr := fromTokenTypeProto(req.Msg.TokenType)
		if convErr != nil {
			telemetry.RecordSpanError(span, convErr, "invalid token type filter")
			span.SetStatus(codes.Error, "invalid token type filter")
			return nil, connect.NewError(connect.CodeInvalidArgument, convErr)
		}
		dbMappers, err = s.mapperRepo.GetMappersByTokenType(ctx, tokenType)
	case req.Msg.ClientId != "":
		dbMappers, err = s.mapperRepo.GetClientMappers(ctx, req.Msg.ClientId)
	default:
		// The user_attribute filter is applied in memory below.
		dbMappers, err = s.mapperRepo.ListAllMappers(ctx)
	}
	if err != nil {
		telemetry.RecordSpanError(span, err, "repository error listing user attribute mappers")
		span.SetStatus(codes.Error, "failed to list user attribute mappers")
		log.Ctx(ctx).Error().Err(err).Msg("ListUserAttributeMappers: repository error")
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to list user attribute mappers: %w", err))
	}

	filtered := make([]*domain.UserAttributeMapper, 0, len(dbMappers))
	for _, m := range dbMappers {
		if req.Msg.UserAttribute != "" && m.UserAttribute != req.Msg.UserAttribute {
			continue
		}
		filtered = append(filtered, m)
	}

	pageSize := normalizePageSize(req.Msg.PageSize)
	offset := pageOffsetFromToken(req.Msg.PageToken)
	page, nextToken := paginate(filtered, offset, pageSize)

	protos := make([]*ssov1.UserAttributeMapper, len(page))
	for i, m := range page {
		protos[i] = toUserAttributeMapperProto(m)
	}

	return connect.NewResponse(&ssov1.ListUserAttributeMappersResponse{
		UserAttributeMappers: protos,
		NextPageToken:        nextToken,
	}), nil
}

// UpdateUserAttributeMapper updates an existing user attribute mapper.
func (s *UserAttributeServiceServer) UpdateUserAttributeMapper(ctx context.Context, req *connect.Request[ssov1.UpdateUserAttributeMapperRequest]) (*connect.Response[ssov1.UpdateUserAttributeMapperResponse], error) {
	ctx, span := telemetry.StartSpan(ctx, userAttributeServiceTracerName, "UpdateUserAttributeMapper", attribute.String("mapper.id", req.Msg.Id))
	defer span.End()

	if req.Msg.Name == nil && req.Msg.UserAttribute == nil && req.Msg.TokenClaimName == nil &&
		req.Msg.TokenType == nil && req.Msg.MultiValued == nil && req.Msg.Protocol == nil && req.Msg.ClientId == nil {
		err := errors.New("at least one field must be provided for update")
		telemetry.RecordSpanError(span, err, "invalid update user attribute mapper request")
		span.SetStatus(codes.Error, "invalid update user attribute mapper request")
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	dbMapper, err := s.mapperRepo.GetMapperByID(ctx, req.Msg.Id)
	if err != nil {
		telemetry.RecordSpanError(span, err, "failed to retrieve user attribute mapper for update")
		span.SetStatus(codes.Error, "user attribute mapper not found for update")
		if isNotFoundError(err) {
			log.Ctx(ctx).Warn().Err(err).Str("mapperID", req.Msg.Id).Msg("User attribute mapper not found for update")
			return nil, connect.NewError(connect.CodeNotFound, errors.New("user attribute mapper not found for update"))
		}
		log.Ctx(ctx).Error().Err(err).Str("mapperID", req.Msg.Id).Msg("Failed to retrieve user attribute mapper for update")
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to retrieve user attribute mapper for update"))
	}

	if req.Msg.Name != nil {
		dbMapper.Name = *req.Msg.Name
	}
	if req.Msg.UserAttribute != nil {
		dbMapper.UserAttribute = *req.Msg.UserAttribute
	}
	if req.Msg.TokenClaimName != nil {
		dbMapper.TokenClaimName = *req.Msg.TokenClaimName
	}
	if req.Msg.TokenType != nil {
		tokenType, convErr := fromTokenTypeProto(*req.Msg.TokenType)
		if convErr != nil {
			telemetry.RecordSpanError(span, convErr, "invalid token type specified")
			span.SetStatus(codes.Error, "invalid token type specified")
			return nil, connect.NewError(connect.CodeInvalidArgument, convErr)
		}
		dbMapper.TokenType = tokenType
	}
	if req.Msg.MultiValued != nil {
		dbMapper.MultiValued = *req.Msg.MultiValued
	}
	if req.Msg.Protocol != nil {
		protocol, convErr := fromProtocolProto(*req.Msg.Protocol)
		if convErr != nil {
			telemetry.RecordSpanError(span, convErr, "invalid protocol specified")
			span.SetStatus(codes.Error, "invalid protocol specified")
			return nil, connect.NewError(connect.CodeInvalidArgument, convErr)
		}
		dbMapper.Protocol = protocol
	}
	if req.Msg.ClientId != nil {
		dbMapper.ClientID = *req.Msg.ClientId
	}

	if err := s.mapperRepo.UpdateMapper(ctx, dbMapper); err != nil {
		telemetry.RecordSpanError(span, err, "failed to update user attribute mapper in repository")
		span.SetStatus(codes.Error, "failed to update user attribute mapper")
		log.Ctx(ctx).Error().Err(err).Str("mapperID", dbMapper.ID).Msg("Failed to update user attribute mapper in repository")
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to update user attribute mapper"))
	}

	return connect.NewResponse(&ssov1.UpdateUserAttributeMapperResponse{UserAttributeMapper: toUserAttributeMapperProto(dbMapper)}), nil
}

// DeleteUserAttributeMapper deletes a user attribute mapper by its ID.
func (s *UserAttributeServiceServer) DeleteUserAttributeMapper(ctx context.Context, req *connect.Request[ssov1.DeleteUserAttributeMapperRequest]) (*connect.Response[emptypb.Empty], error) {
	ctx, span := telemetry.StartSpan(ctx, userAttributeServiceTracerName, "DeleteUserAttributeMapper", attribute.String("mapper.id", req.Msg.Id))
	defer span.End()

	if err := s.mapperRepo.DeleteMapper(ctx, req.Msg.Id); err != nil {
		telemetry.RecordSpanError(span, err, "failed to delete user attribute mapper from repository")
		span.SetStatus(codes.Error, "failed to delete user attribute mapper")
		if isNotFoundError(err) {
			log.Ctx(ctx).Warn().Err(err).Str("mapperID", req.Msg.Id).Msg("User attribute mapper not found for deletion")
			return nil, connect.NewError(connect.CodeNotFound, errors.New("user attribute mapper not found for deletion"))
		}
		log.Ctx(ctx).Error().Err(err).Str("mapperID", req.Msg.Id).Msg("Failed to delete user attribute mapper from repository")
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to delete user attribute mapper"))
	}
	log.Ctx(ctx).Info().Str("mapperID", req.Msg.Id).Msg("User attribute mapper deleted successfully")
	return connect.NewResponse(&emptypb.Empty{}), nil
}

// toUserAttributeProto converts a domain user attribute to its proto
// representation. The domain type carries no timestamps, so created_at and
// updated_at are left unset.
func toUserAttributeProto(a *domain.UserAttribute) *ssov1.UserAttribute {
	if a == nil {
		return nil
	}
	return &ssov1.UserAttribute{
		Id:     a.ID,
		Name:   a.Name,
		Value:  a.Value,
		UserId: a.UserID,
	}
}

// fromCreateUserAttributeRequest converts a create request into a domain user
// attribute. The ID is left empty; the repository assigns it.
func fromCreateUserAttributeRequest(msg *ssov1.CreateUserAttributeRequest) *domain.UserAttribute {
	return &domain.UserAttribute{
		Name:   msg.Name,
		Value:  msg.Value,
		UserID: msg.UserId,
	}
}

// toUserAttributeMapperProto converts a domain user attribute mapper to its
// proto representation.
func toUserAttributeMapperProto(m *domain.UserAttributeMapper) *ssov1.UserAttributeMapper {
	if m == nil {
		return nil
	}
	proto := &ssov1.UserAttributeMapper{
		Id:             m.ID,
		Name:           m.Name,
		UserAttribute:  m.UserAttribute,
		TokenClaimName: m.TokenClaimName,
		TokenType:      toTokenTypeProto(m.TokenType),
		MultiValued:    m.MultiValued,
		Protocol:       toProtocolProto(m.Protocol),
		ClientId:       m.ClientID,
	}
	if !m.CreatedAt.IsZero() {
		proto.CreatedAt = timestamppb.New(m.CreatedAt)
	}
	if !m.UpdatedAt.IsZero() {
		proto.UpdatedAt = timestamppb.New(m.UpdatedAt)
	}
	return proto
}

// fromCreateUserAttributeMapperRequest converts a create request into a domain
// user attribute mapper. The protocol defaults to openid-connect and
// multi_valued to false when unset; the repository assigns the ID and
// timestamps.
func fromCreateUserAttributeMapperRequest(msg *ssov1.CreateUserAttributeMapperRequest) (*domain.UserAttributeMapper, error) {
	if msg.Name == "" || msg.UserAttribute == "" || msg.TokenClaimName == "" {
		return nil, errors.New("name, user_attribute and token_claim_name are required")
	}

	tokenType, err := fromTokenTypeProto(msg.TokenType)
	if err != nil {
		return nil, err
	}

	protocol := userAttributeProtocolOIDC
	if msg.Protocol != nil {
		protocol, err = fromProtocolProto(*msg.Protocol)
		if err != nil {
			return nil, err
		}
	}

	multiValued := false
	if msg.MultiValued != nil {
		multiValued = *msg.MultiValued
	}

	var clientID string
	if msg.ClientId != nil {
		clientID = *msg.ClientId
	}

	return &domain.UserAttributeMapper{
		Name:           msg.Name,
		UserAttribute:  msg.UserAttribute,
		TokenClaimName: msg.TokenClaimName,
		TokenType:      tokenType,
		MultiValued:    multiValued,
		Protocol:       protocol,
		ClientID:       clientID,
	}, nil
}

// fromTokenTypeProto maps the proto token type enum to the canonical string
// value stored in the domain layer (see userAttributeTokenType* constants).
func fromTokenTypeProto(tokenType ssov1.TokenTypeProto) (string, error) {
	switch tokenType {
	case ssov1.TokenTypeProto_TOKEN_TYPE_ID_TOKEN:
		return userAttributeTokenTypeIDToken, nil
	case ssov1.TokenTypeProto_TOKEN_TYPE_ACCESS_TOKEN:
		return userAttributeTokenTypeAccessToken, nil
	case ssov1.TokenTypeProto_TOKEN_TYPE_USERINFO:
		return userAttributeTokenTypeUserInfo, nil
	default:
		return "", errors.New("invalid token type specified")
	}
}

// toTokenTypeProto maps a domain token type string to the proto token type enum.
func toTokenTypeProto(tokenType string) ssov1.TokenTypeProto {
	switch tokenType {
	case userAttributeTokenTypeIDToken:
		return ssov1.TokenTypeProto_TOKEN_TYPE_ID_TOKEN
	case userAttributeTokenTypeAccessToken:
		return ssov1.TokenTypeProto_TOKEN_TYPE_ACCESS_TOKEN
	case userAttributeTokenTypeUserInfo:
		return ssov1.TokenTypeProto_TOKEN_TYPE_USERINFO
	default:
		return ssov1.TokenTypeProto_TOKEN_TYPE_UNSPECIFIED
	}
}

// fromProtocolProto maps the proto protocol enum to the canonical string value
// stored in the domain layer.
func fromProtocolProto(protocol ssov1.ProtocolProto) (string, error) {
	switch protocol {
	case ssov1.ProtocolProto_PROTOCOL_OPENID_CONNECT:
		return userAttributeProtocolOIDC, nil
	default:
		return "", errors.New("invalid protocol specified")
	}
}

// toProtocolProto maps a domain protocol string to the proto protocol enum.
func toProtocolProto(protocol string) ssov1.ProtocolProto {
	if protocol == userAttributeProtocolOIDC {
		return ssov1.ProtocolProto_PROTOCOL_OPENID_CONNECT
	}
	return ssov1.ProtocolProto_PROTOCOL_UNSPECIFIED
}

// isNotFoundError reports whether err indicates a missing record. It covers
// the mongo repository's ErrNoDocuments ("mongo: no documents in result") as
// well as repository errors that surface "not found".
func isNotFoundError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "not found") || strings.Contains(msg, "no documents")
}

// normalizePageSize clamps a requested page size to
// [1, userAttributeMaxPageSize], defaulting to userAttributeDefaultPageSize
// when unset or invalid.
func normalizePageSize(pageSize int32) int {
	if pageSize <= 0 {
		return userAttributeDefaultPageSize
	}
	if pageSize > userAttributeMaxPageSize {
		return userAttributeMaxPageSize
	}
	return int(pageSize)
}

// pageOffsetFromToken decodes an offset-based page token.
func pageOffsetFromToken(token string) int {
	if token == "" {
		return 0
	}
	offset, err := strconv.Atoi(token)
	if err != nil || offset < 0 {
		return 0
	}
	return offset
}

// paginate returns the items for the requested page and the next page token,
// which is empty when no further pages exist.
func paginate[T any](items []T, offset, pageSize int) ([]T, string) {
	if offset >= len(items) {
		return nil, ""
	}
	end := offset + pageSize
	if end > len(items) {
		end = len(items)
	}
	nextToken := ""
	if end < len(items) {
		nextToken = strconv.Itoa(end)
	}
	return items[offset:end], nextToken
}
