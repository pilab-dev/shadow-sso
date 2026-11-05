package services

import (
	"context"
	"errors"

	"connectrpc.com/connect"
	"github.com/pilab-dev/shadow-sso/domain"
	ssov1 "github.com/pilab-dev/shadow-sso/gen/proto/sso/v1"
	"github.com/pilab-dev/shadow-sso/gen/proto/sso/v1/ssov1connect"
)

// CIBAServer implements ssov1connect.BackchannelAuthenticationServiceHandler.
type CIBAServer struct {
	ssov1connect.UnimplementedBackchannelAuthenticationServiceHandler
	svc CIBAService
}

// NewCIBAServer creates the gRPC front of a CIBAService.
func NewCIBAServer(svc CIBAService) *CIBAServer { return &CIBAServer{svc: svc} }

var _ ssov1connect.BackchannelAuthenticationServiceHandler = (*CIBAServer)(nil)

func (s *CIBAServer) GetBackchannelAuthentication(ctx context.Context, req *connect.Request[ssov1.GetBackchannelAuthenticationRequest]) (*connect.Response[ssov1.GetBackchannelAuthenticationResponse], error) {
	d, meta, err := s.svc.GetBackchannelAuth(ctx, req.Msg.AuthReqId)
	if err != nil {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("backchannel authentication request not found"))
	}
	return connect.NewResponse(&ssov1.GetBackchannelAuthenticationResponse{
		ClientId:       d.ClientID,
		UserId:         meta.Subject,
		Scope:          d.Scope,
		BindingMessage: meta.BindingMessage,
		Status:         string(d.Status),
		ExpiresAt:      d.ExpiresAt.Unix(),
	}), nil
}

func (s *CIBAServer) ResolveBackchannelAuthentication(ctx context.Context, req *connect.Request[ssov1.ResolveBackchannelAuthenticationRequest]) (*connect.Response[ssov1.ResolveBackchannelAuthenticationResponse], error) {
	err := s.svc.ResolveBackchannelAuth(ctx, req.Msg.AuthReqId, req.Msg.UserId, req.Msg.Approve)
	switch {
	case err == nil:
		return connect.NewResponse(&ssov1.ResolveBackchannelAuthenticationResponse{}), nil
	case errors.Is(err, domain.ErrDeviceCodeNotFound):
		return nil, connect.NewError(connect.CodeNotFound, errors.New("backchannel authentication request not found"))
	case errors.Is(err, domain.ErrCannotApproveDeviceAuth):
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("request is no longer pending"))
	default:
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to resolve request"))
	}
}
