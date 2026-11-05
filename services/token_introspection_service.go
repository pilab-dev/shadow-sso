package services

import (
	"context"
	"errors"
	"time"

	"connectrpc.com/connect"
	"github.com/pilab-dev/shadow-sso/domain"
	ssov1 "github.com/pilab-dev/shadow-sso/gen/proto/sso/v1"
	"github.com/pilab-dev/shadow-sso/gen/proto/sso/v1/ssov1connect"
	"github.com/pilab-dev/shadow-sso/internal/telemetry"
	"go.opentelemetry.io/otel/attribute"
)

const tokenIntrospectionTracerName = "token-introspection-service"

// TokenIntrospectionServiceServer implements ssov1.TokenIntrospectionService.
type TokenIntrospectionServiceServer struct {
	ssov1connect.UnimplementedTokenIntrospectionServiceHandler
	tokenService TokenService
	userRepo     domain.UserRepository // optional; resolves the username
	issuer       string
}

// NewTokenIntrospectionServer creates the admin token introspection service.
// userRepo may be nil, in which case username is left empty.
func NewTokenIntrospectionServer(tokenService TokenService, userRepo domain.UserRepository, issuer string) *TokenIntrospectionServiceServer {
	return &TokenIntrospectionServiceServer{tokenService: tokenService, userRepo: userRepo, issuer: issuer}
}

var _ ssov1connect.TokenIntrospectionServiceHandler = (*TokenIntrospectionServiceServer)(nil)

// IntrospectToken introspects any token (regardless of the issuing client).
// Unknown, revoked and expired tokens yield active=false rather than an error.
func (s *TokenIntrospectionServiceServer) IntrospectToken(ctx context.Context, req *connect.Request[ssov1.IntrospectTokenRequest]) (*connect.Response[ssov1.IntrospectTokenResponse], error) {
	ctx, span := telemetry.StartSpan(ctx, tokenIntrospectionTracerName, "IntrospectToken",
		attribute.String("oauth.token_type_hint", req.Msg.GetTokenTypeHint()))
	defer span.End()

	if req.Msg.GetToken() == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("token is required"))
	}

	var (
		info *domain.TokenInfo
		err  error
	)
	token := req.Msg.GetToken()
	switch req.Msg.GetTokenTypeHint() {
	case "refresh_token":
		info, err = s.tokenService.GetRefreshTokenInfo(ctx, token)
	default:
		info, err = s.tokenService.GetAccessTokenInfo(ctx, token)
		if err != nil {
			info, err = s.tokenService.GetRefreshTokenInfo(ctx, token)
		}
	}
	if err != nil || info == nil || info.IsRevoked || time.Now().After(info.ExpiresAt) {
		span.SetAttributes(attribute.Bool("token.active", false))
		return connect.NewResponse(&ssov1.IntrospectTokenResponse{Active: false}), nil
	}
	span.SetAttributes(attribute.Bool("token.active", true), attribute.String("user.id", info.UserID))

	username := ""
	if s.userRepo != nil && info.UserID != "" {
		if user, uerr := s.userRepo.GetUserByID(ctx, info.UserID); uerr == nil && user != nil {
			username = user.Email
		}
	}

	res := domain.TokenIntrospection{
		Active:               true,
		Scope:                info.Scope,
		ClientID:             info.ClientID,
		Username:             username,
		TokenType:            info.TokenType,
		Exp:                  info.ExpiresAt.Unix(),
		Iat:                  info.IssuedAt.Unix(),
		Nbf:                  info.IssuedAt.Unix(),
		Sub:                  info.UserID,
		Aud:                  info.ClientID,
		Iss:                  s.issuer,
		Jti:                  info.ID,
		AuthorizationDetails: []byte(info.AuthorizationDetails),
	}
	return connect.NewResponse(toIntrospectTokenProto(&res)), nil
}

func toIntrospectTokenProto(t *domain.TokenIntrospection) *ssov1.IntrospectTokenResponse {
	return &ssov1.IntrospectTokenResponse{
		Active:               t.Active,
		Scope:                t.Scope,
		ClientId:             t.ClientID,
		Username:             t.Username,
		TokenType:            t.TokenType,
		Exp:                  t.Exp,
		Iat:                  t.Iat,
		Nbf:                  t.Nbf,
		Sub:                  t.Sub,
		Aud:                  t.Aud,
		Iss:                  t.Iss,
		Jti:                  t.Jti,
		AuthorizationDetails: string(t.AuthorizationDetails),
	}
}
