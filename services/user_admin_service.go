package services

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/pilab-dev/shadow-sso/domain"
	ssov1 "github.com/pilab-dev/shadow-sso/gen/proto/sso/v1"
	"github.com/pilab-dev/shadow-sso/gen/proto/sso/v1/ssov1connect"
	"github.com/pilab-dev/shadow-sso/internal/audit"
	"github.com/pilab-dev/shadow-sso/internal/telemetry"
	pkgauth "github.com/pilab-dev/shadow-sso/pkg/auth"
	"github.com/rs/zerolog/log"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"google.golang.org/protobuf/types/known/emptypb"
)

const userAdminServiceTracerName = "user-admin-service"

// UserAdminServiceServer implements ssov1.UserAdminService.
type UserAdminServiceServer struct {
	ssov1connect.UnimplementedUserAdminServiceHandler
	userRepo      domain.UserRepository
	hasher        domain.PasswordHasher
	emailService  domain.EmailService
	publicBaseURL string
}

// NewUserAdminServer creates the user admin service. emailService may be nil,
// in which case the email RPCs return FailedPrecondition.
func NewUserAdminServer(userRepo domain.UserRepository, hasher domain.PasswordHasher, emailService domain.EmailService, publicBaseURL string) *UserAdminServiceServer {
	return &UserAdminServiceServer{
		userRepo:      userRepo,
		hasher:        hasher,
		emailService:  emailService,
		publicBaseURL: strings.TrimRight(publicBaseURL, "/"),
	}
}

var _ ssov1connect.UserAdminServiceHandler = (*UserAdminServiceServer)(nil)

func (s *UserAdminServiceServer) loadUser(ctx context.Context, userID string) (*domain.User, error) {
	if strings.TrimSpace(userID) == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("user_id is required"))
	}
	user, err := s.userRepo.GetUserByID(ctx, userID)
	if err != nil {
		if isNotFoundError(err) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("user not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to retrieve user"))
	}
	if user == nil {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("user not found"))
	}
	return user, nil
}

func (s *UserAdminServiceServer) saveUser(ctx context.Context, user *domain.User, action string) error {
	if err := s.userRepo.UpdateUser(ctx, user); err != nil {
		log.Ctx(ctx).Error().Err(err).Str("userID", user.ID).Str("action", action).Msg("Failed to update user")
		audit.Log("User", action, "", user.ID, user.Email, false, err)
		return connect.NewError(connect.CodeInternal, errors.New("failed to update user"))
	}
	audit.Log("User", action, "", user.ID, user.Email, true, nil)
	return nil
}

func (s *UserAdminServiceServer) sendEmail(ctx context.Context, userID, spanName, path string, expiry time.Duration,
	store func(ctx context.Context, userID, digest string, expiresAt time.Time) error,
	send func(to, name, link string) error,
) (*connect.Response[emptypb.Empty], error) {
	ctx, span := telemetry.StartSpan(ctx, userAdminServiceTracerName, spanName, attribute.String("user.id", userID))
	defer span.End()

	if s.emailService == nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("email delivery is not configured"))
	}
	user, err := s.loadUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	// Single-use token; only its digest is stored.
	token, digest, err := pkgauth.NewEmailToken()
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to generate token"))
	}
	if err := store(ctx, userID, digest, time.Now().Add(expiry)); err != nil {
		telemetry.RecordSpanError(span, err, "failed to store token")
		span.SetStatus(codes.Error, "failed to store token")
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to store token"))
	}
	link := s.publicBaseURL + path + "?token=" + url.QueryEscape(token)
	if err := send(user.Email, user.FirstName, link); err != nil {
		telemetry.RecordSpanError(span, err, "failed to send email")
		span.SetStatus(codes.Error, "failed to send email")
		audit.Log("User", spanName, "", user.ID, user.Email, false, err)
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to send email"))
	}
	audit.Log("User", spanName, "", user.ID, user.Email, true, nil)
	return connect.NewResponse(&emptypb.Empty{}), nil
}

// SendVerificationEmail emails the user a verification link.
func (s *UserAdminServiceServer) SendVerificationEmail(ctx context.Context, req *connect.Request[ssov1.SendVerificationEmailRequest]) (*connect.Response[emptypb.Empty], error) {
	return s.sendEmail(ctx, req.Msg.GetUserId(), "SendVerificationEmail", "/verify-email", 24*time.Hour,
		func(ctx context.Context, id, digest string, exp time.Time) error {
			return s.userRepo.StoreEmailVerificationToken(ctx, id, digest, exp)
		}, func(to, name, link string) error {
			return s.emailService.SendVerificationEmail(to, name, link)
		})
}

// SendPasswordResetEmail emails the user a password reset link.
func (s *UserAdminServiceServer) SendPasswordResetEmail(ctx context.Context, req *connect.Request[ssov1.SendPasswordResetEmailRequest]) (*connect.Response[emptypb.Empty], error) {
	return s.sendEmail(ctx, req.Msg.GetUserId(), "SendPasswordResetEmail", "/reset-password", time.Hour,
		func(ctx context.Context, id, digest string, exp time.Time) error {
			return s.userRepo.StorePasswordResetToken(ctx, id, digest, exp)
		}, func(to, name, link string) error {
			return s.emailService.SendPasswordResetEmail(to, name, link)
		})
}

func (s *UserAdminServiceServer) setPassword(ctx context.Context, userID, password, spanName string, apply func(u *domain.User)) (*connect.Response[emptypb.Empty], error) {
	ctx, span := telemetry.StartSpan(ctx, userAdminServiceTracerName, spanName, attribute.String("user.id", userID))
	defer span.End()

	if password == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("password is required"))
	}
	user, err := s.loadUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	hash, err := s.hasher.Hash(password)
	if err != nil {
		telemetry.RecordSpanError(span, err, "failed to hash password")
		span.SetStatus(codes.Error, "failed to hash password")
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to hash password"))
	}
	user.PasswordHash = hash
	apply(user)
	if err := s.saveUser(ctx, user, spanName); err != nil {
		span.SetStatus(codes.Error, "failed to update user")
		return nil, err
	}
	return connect.NewResponse(&emptypb.Empty{}), nil
}

// AdminResetPassword sets a new password and clears any pending reset token.
func (s *UserAdminServiceServer) AdminResetPassword(ctx context.Context, req *connect.Request[ssov1.AdminResetPasswordRequest]) (*connect.Response[emptypb.Empty], error) {
	return s.setPassword(ctx, req.Msg.GetUserId(), req.Msg.GetNewPassword(), "AdminResetPassword", func(u *domain.User) {
		u.PasswordResetToken = ""
	})
}

// SetUserPassword sets a password, optionally forcing a change at next login.
func (s *UserAdminServiceServer) SetUserPassword(ctx context.Context, req *connect.Request[ssov1.SetUserPasswordRequest]) (*connect.Response[emptypb.Empty], error) {
	temporary := req.Msg.GetTemporary()
	return s.setPassword(ctx, req.Msg.GetUserId(), req.Msg.GetPassword(), "SetUserPassword", func(u *domain.User) {
		if temporary {
			u.AddRequiredAction(domain.RequiredActionUpdatePassword)
		} else {
			u.RemoveRequiredAction(domain.RequiredActionUpdatePassword)
		}
	})
}

func (s *UserAdminServiceServer) mutateActions(ctx context.Context, userID, spanName string, validate []string, apply func(u *domain.User)) (*connect.Response[emptypb.Empty], error) {
	ctx, span := telemetry.StartSpan(ctx, userAdminServiceTracerName, spanName, attribute.String("user.id", userID))
	defer span.End()

	for _, a := range validate {
		if !domain.IsKnownRequiredAction(a) {
			return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("unknown required action "+a))
		}
	}
	user, err := s.loadUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	apply(user)
	if err := s.saveUser(ctx, user, spanName); err != nil {
		span.SetStatus(codes.Error, "failed to update user")
		return nil, err
	}
	return connect.NewResponse(&emptypb.Empty{}), nil
}

// ExecuteActions queues required actions for the user's next login.
func (s *UserAdminServiceServer) ExecuteActions(ctx context.Context, req *connect.Request[ssov1.ExecuteActionsRequest]) (*connect.Response[emptypb.Empty], error) {
	actions := req.Msg.GetActions()
	return s.mutateActions(ctx, req.Msg.GetUserId(), "ExecuteActions", actions, func(u *domain.User) {
		for _, a := range actions {
			u.AddRequiredAction(a)
		}
	})
}

// AddRequiredAction adds one required action.
func (s *UserAdminServiceServer) AddRequiredAction(ctx context.Context, req *connect.Request[ssov1.AddRequiredActionRequest]) (*connect.Response[emptypb.Empty], error) {
	action := req.Msg.GetAction()
	return s.mutateActions(ctx, req.Msg.GetUserId(), "AddRequiredAction", []string{action}, func(u *domain.User) {
		u.AddRequiredAction(action)
	})
}

// RemoveRequiredAction removes one required action.
func (s *UserAdminServiceServer) RemoveRequiredAction(ctx context.Context, req *connect.Request[ssov1.RemoveRequiredActionRequest]) (*connect.Response[emptypb.Empty], error) {
	action := req.Msg.GetAction()
	return s.mutateActions(ctx, req.Msg.GetUserId(), "RemoveRequiredAction", nil, func(u *domain.User) {
		u.RemoveRequiredAction(action)
	})
}

// DeleteUserCredential removes a stored MFA method / credential.
func (s *UserAdminServiceServer) DeleteUserCredential(ctx context.Context, req *connect.Request[ssov1.DeleteUserCredentialRequest]) (*connect.Response[emptypb.Empty], error) {
	ctx, span := telemetry.StartSpan(ctx, userAdminServiceTracerName, "DeleteUserCredential",
		attribute.String("user.id", req.Msg.GetUserId()))
	defer span.End()

	if strings.TrimSpace(req.Msg.GetUserId()) == "" || strings.TrimSpace(req.Msg.GetCredentialId()) == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("user_id and credential_id are required"))
	}
	if err := s.userRepo.RemoveMfaMethod(ctx, req.Msg.GetUserId(), req.Msg.GetCredentialId()); err != nil {
		telemetry.RecordSpanError(span, err, "failed to delete credential")
		span.SetStatus(codes.Error, "failed to delete credential")
		audit.Log("User", "DeleteUserCredential", "", req.Msg.GetUserId(), "", false, err)
		if isNotFoundError(err) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("credential not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to delete credential"))
	}
	audit.Log("User", "DeleteUserCredential", "", req.Msg.GetUserId(), req.Msg.GetCredentialId(), true, nil)
	return connect.NewResponse(&emptypb.Empty{}), nil
}
