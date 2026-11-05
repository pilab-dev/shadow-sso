package services

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"connectrpc.com/connect"
	"github.com/pilab-dev/shadow-sso/domain"
	ssov1 "github.com/pilab-dev/shadow-sso/gen/proto/sso/v1"
	"github.com/pilab-dev/shadow-sso/gen/proto/sso/v1/ssov1connect"
	"github.com/pilab-dev/shadow-sso/internal/audit"
	"github.com/pilab-dev/shadow-sso/internal/telemetry"
	"github.com/rs/zerolog/log"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	protocolMapperServiceTracerName = "protocol-mapper-service"
	protocolMapperDefaultProtocol   = "openid-connect"
)

// ProtocolMapperServiceServer implements ssov1.ProtocolMapperService.
type ProtocolMapperServiceServer struct {
	ssov1connect.UnimplementedProtocolMapperServiceHandler

	mapperRepo domain.ProtocolMapperRepository
	clientRepo domain.ClientRepository // optional; validates client_id when set
}

// NewProtocolMapperServer creates the protocol mapper admin service. clientRepo
// may be nil, in which case client_id values are not validated.
func NewProtocolMapperServer(mapperRepo domain.ProtocolMapperRepository, clientRepo domain.ClientRepository) *ProtocolMapperServiceServer {
	return &ProtocolMapperServiceServer{mapperRepo: mapperRepo, clientRepo: clientRepo}
}

var _ ssov1connect.ProtocolMapperServiceHandler = (*ProtocolMapperServiceServer)(nil)

// CreateProtocolMapper creates a realm-wide or client-specific mapper.
func (s *ProtocolMapperServiceServer) CreateProtocolMapper(ctx context.Context, req *connect.Request[ssov1.CreateProtocolMapperRequest]) (*connect.Response[ssov1.CreateProtocolMapperResponse], error) {
	ctx, span := telemetry.StartSpan(ctx, protocolMapperServiceTracerName, "CreateProtocolMapper",
		attribute.String("mapper.name", req.Msg.GetName()),
		attribute.String("mapper.type", req.Msg.GetProtocolMapper()),
	)
	defer span.End()

	mapper, err := s.mapperFromCreateRequest(ctx, req.Msg)
	if err != nil {
		telemetry.RecordSpanError(span, err, "invalid create protocol mapper request")
		span.SetStatus(codes.Error, "invalid create protocol mapper request")
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	if err := s.mapperRepo.CreateProtocolMapper(ctx, mapper); err != nil {
		telemetry.RecordSpanError(span, err, "failed to create protocol mapper")
		span.SetStatus(codes.Error, "failed to create protocol mapper")
		log.Ctx(ctx).Error().Err(err).Str("mapperName", mapper.Name).Msg("Failed to create protocol mapper")
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to create protocol mapper"))
	}

	audit.Log("ProtocolMapper", "ProtocolMapperCreated", "", mapper.ID, mapper.Name, true, nil)
	return connect.NewResponse(&ssov1.CreateProtocolMapperResponse{
		ProtocolMapper: toProtocolMapperProto(mapper),
	}), nil
}

// GetProtocolMapper returns one mapper by ID.
func (s *ProtocolMapperServiceServer) GetProtocolMapper(ctx context.Context, req *connect.Request[ssov1.GetProtocolMapperRequest]) (*connect.Response[ssov1.GetProtocolMapperResponse], error) {
	ctx, span := telemetry.StartSpan(ctx, protocolMapperServiceTracerName, "GetProtocolMapper",
		attribute.String("mapper.id", req.Msg.GetId()))
	defer span.End()

	mapper, err := s.mapperRepo.GetProtocolMapperByID(ctx, req.Msg.GetId())
	if err != nil {
		telemetry.RecordSpanError(span, err, "failed to get protocol mapper")
		span.SetStatus(codes.Error, "failed to retrieve protocol mapper")
		if isNotFoundError(err) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("protocol mapper not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to retrieve protocol mapper"))
	}
	return connect.NewResponse(&ssov1.GetProtocolMapperResponse{
		ProtocolMapper: toProtocolMapperProto(mapper),
	}), nil
}

// ListProtocolMappers returns all mappers, the effective set for a client, or
// only realm-wide mappers.
func (s *ProtocolMapperServiceServer) ListProtocolMappers(ctx context.Context, req *connect.Request[ssov1.ListProtocolMappersRequest]) (*connect.Response[ssov1.ListProtocolMappersResponse], error) {
	ctx, span := telemetry.StartSpan(ctx, protocolMapperServiceTracerName, "ListProtocolMappers",
		attribute.String("client.id", req.Msg.GetClientId()),
		attribute.Bool("realm.only", req.Msg.GetRealmOnly()),
	)
	defer span.End()

	if req.Msg.GetClientId() != "" && req.Msg.GetRealmOnly() {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			errors.New("client_id and realm_only are mutually exclusive"))
	}

	var (
		mappers []*domain.ProtocolMapper
		err     error
	)
	switch {
	case req.Msg.GetClientId() != "":
		mappers, err = s.mapperRepo.ListClientProtocolMappers(ctx, req.Msg.GetClientId())
	case req.Msg.GetRealmOnly():
		mappers, err = s.mapperRepo.ListRealmProtocolMappers(ctx)
	default:
		mappers, err = s.mapperRepo.ListProtocolMappers(ctx)
	}
	if err != nil {
		telemetry.RecordSpanError(span, err, "failed to list protocol mappers")
		span.SetStatus(codes.Error, "failed to list protocol mappers")
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to list protocol mappers"))
	}

	sorted := append([]*domain.ProtocolMapper(nil), mappers...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Name == sorted[j].Name {
			return sorted[i].ID < sorted[j].ID
		}
		return sorted[i].Name < sorted[j].Name
	})
	mappers = sorted

	page, nextToken := paginate(mappers, pageOffsetFromToken(req.Msg.GetPageToken()), normalizePageSize(req.Msg.GetPageSize()))
	protos := make([]*ssov1.ProtocolMapper, len(page))
	for i, mapper := range page {
		protos[i] = toProtocolMapperProto(mapper)
	}

	return connect.NewResponse(&ssov1.ListProtocolMappersResponse{
		ProtocolMappers: protos,
		NextPageToken:   nextToken,
	}), nil
}

// UpdateProtocolMapper mutates an existing mapper.
func (s *ProtocolMapperServiceServer) UpdateProtocolMapper(ctx context.Context, req *connect.Request[ssov1.UpdateProtocolMapperRequest]) (*connect.Response[ssov1.UpdateProtocolMapperResponse], error) {
	ctx, span := telemetry.StartSpan(ctx, protocolMapperServiceTracerName, "UpdateProtocolMapper",
		attribute.String("mapper.id", req.Msg.GetId()))
	defer span.End()

	if req.Msg.Name == nil && req.Msg.Protocol == nil && req.Msg.ProtocolMapper == nil &&
		req.Msg.Config == nil && !req.Msg.GetClearConfig() && req.Msg.ClientId == nil {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			errors.New("at least one field must be provided for update"))
	}

	mapper, err := s.mapperRepo.GetProtocolMapperByID(ctx, req.Msg.GetId())
	if err != nil {
		telemetry.RecordSpanError(span, err, "failed to retrieve protocol mapper for update")
		span.SetStatus(codes.Error, "protocol mapper not found")
		if isNotFoundError(err) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("protocol mapper not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to retrieve protocol mapper"))
	}

	if req.Msg.Name != nil {
		if strings.TrimSpace(*req.Msg.Name) == "" {
			return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("name must not be empty"))
		}
		mapper.Name = *req.Msg.Name
	}
	if req.Msg.Protocol != nil {
		mapper.Protocol = *req.Msg.Protocol
	}
	if req.Msg.ProtocolMapper != nil {
		if strings.TrimSpace(*req.Msg.ProtocolMapper) == "" {
			return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("protocol_mapper must not be empty"))
		}
		mapper.ProtocolMapper = *req.Msg.ProtocolMapper
	}
	if req.Msg.Config != nil {
		mapper.Config = protocolMapperConfigFromProto(req.Msg.Config)
	} else if req.Msg.GetClearConfig() {
		mapper.Config = nil
	}
	if req.Msg.ClientId != nil {
		if err := s.validateClientID(ctx, *req.Msg.ClientId); err != nil {
			return nil, connect.NewError(connect.CodeInvalidArgument, err)
		}
		mapper.ClientID = *req.Msg.ClientId
	}

	if err := s.mapperRepo.UpdateProtocolMapper(ctx, mapper); err != nil {
		telemetry.RecordSpanError(span, err, "failed to update protocol mapper")
		span.SetStatus(codes.Error, "failed to update protocol mapper")
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to update protocol mapper"))
	}

	audit.Log("ProtocolMapper", "ProtocolMapperUpdated", "", mapper.ID, mapper.Name, true, nil)
	return connect.NewResponse(&ssov1.UpdateProtocolMapperResponse{
		ProtocolMapper: toProtocolMapperProto(mapper),
	}), nil
}

// DeleteProtocolMapper removes a mapper.
func (s *ProtocolMapperServiceServer) DeleteProtocolMapper(ctx context.Context, req *connect.Request[ssov1.DeleteProtocolMapperRequest]) (*connect.Response[emptypb.Empty], error) {
	ctx, span := telemetry.StartSpan(ctx, protocolMapperServiceTracerName, "DeleteProtocolMapper",
		attribute.String("mapper.id", req.Msg.GetId()))
	defer span.End()

	if err := s.mapperRepo.DeleteProtocolMapper(ctx, req.Msg.GetId()); err != nil {
		telemetry.RecordSpanError(span, err, "failed to delete protocol mapper")
		span.SetStatus(codes.Error, "failed to delete protocol mapper")
		if isNotFoundError(err) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("protocol mapper not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to delete protocol mapper"))
	}

	audit.Log("ProtocolMapper", "ProtocolMapperDeleted", "", req.Msg.GetId(), "", true, nil)
	return connect.NewResponse(&emptypb.Empty{}), nil
}

func (s *ProtocolMapperServiceServer) mapperFromCreateRequest(ctx context.Context, msg *ssov1.CreateProtocolMapperRequest) (*domain.ProtocolMapper, error) {
	if strings.TrimSpace(msg.GetName()) == "" {
		return nil, errors.New("name is required")
	}
	if strings.TrimSpace(msg.GetProtocolMapper()) == "" {
		return nil, errors.New("protocol_mapper is required")
	}
	protocol := msg.GetProtocol()
	if strings.TrimSpace(protocol) == "" {
		protocol = protocolMapperDefaultProtocol
	}
	clientID := ""
	if msg.ClientId != nil {
		clientID = *msg.ClientId
	}
	if err := s.validateClientID(ctx, clientID); err != nil {
		return nil, err
	}
	return &domain.ProtocolMapper{
		Name:           msg.GetName(),
		Protocol:       protocol,
		ProtocolMapper: msg.GetProtocolMapper(),
		Config:         protocolMapperConfigFromProto(msg.GetConfig()),
		ClientID:       clientID,
	}, nil
}

func (s *ProtocolMapperServiceServer) validateClientID(ctx context.Context, clientID string) error {
	if clientID == "" || s.clientRepo == nil {
		return nil
	}
	if _, err := s.clientRepo.GetClient(ctx, clientID); err != nil {
		return fmt.Errorf("client %q does not exist", clientID)
	}
	return nil
}

func toProtocolMapperProto(m *domain.ProtocolMapper) *ssov1.ProtocolMapper {
	if m == nil {
		return nil
	}
	out := &ssov1.ProtocolMapper{
		Id:             m.ID,
		Name:           m.Name,
		Protocol:       m.Protocol,
		ProtocolMapper: m.ProtocolMapper,
		Config:         protocolMapperConfigToProto(m.Config),
		ClientId:       m.ClientID,
	}
	if !m.CreatedAt.IsZero() {
		out.CreatedAt = timestamppb.New(m.CreatedAt)
	}
	if !m.UpdatedAt.IsZero() {
		out.UpdatedAt = timestamppb.New(m.UpdatedAt)
	}
	return out
}

func protocolMapperConfigToProto(cfg map[string]any) map[string]string {
	if len(cfg) == 0 {
		return nil
	}
	out := make(map[string]string, len(cfg))
	for k, v := range cfg {
		out[k] = fmt.Sprintf("%v", v)
	}
	return out
}

func protocolMapperConfigFromProto(cfg map[string]string) map[string]any {
	if len(cfg) == 0 {
		return nil
	}
	out := make(map[string]any, len(cfg))
	for k, v := range cfg {
		out[k] = v
	}
	return out
}
