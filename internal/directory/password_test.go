package directory

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/require"

	"github.com/pilab-dev/shadow-sso/domain"
	credentialsv1 "github.com/pilab-dev/shadow-sso/internal/directory/gen/pirectory/credentials/v1"
	credentialsv1connect "github.com/pilab-dev/shadow-sso/internal/directory/gen/pirectory/credentials/v1/credentialsv1connect"
	"github.com/pilab-dev/shadow-sso/internal/identity"
)

type pwCredentials struct {
	credentialsv1connect.UnimplementedCredentialsServiceHandler
	change    *credentialsv1.ChangePasswordResponse
	setErr    error
	setViol   []string
	changeReq *credentialsv1.ChangePasswordRequest
	setReq    *credentialsv1.SetPasswordRequest
}

func (f *pwCredentials) ChangePassword(_ context.Context, req *connect.Request[credentialsv1.ChangePasswordRequest]) (*connect.Response[credentialsv1.ChangePasswordResponse], error) {
	f.changeReq = req.Msg
	return connect.NewResponse(f.change), nil
}

func (f *pwCredentials) SetPassword(_ context.Context, req *connect.Request[credentialsv1.SetPasswordRequest]) (*connect.Response[credentialsv1.SetPasswordResponse], error) {
	f.setReq = req.Msg
	if f.setErr != nil {
		return nil, f.setErr
	}
	return connect.NewResponse(&credentialsv1.SetPasswordResponse{PolicyViolations: f.setViol}), nil
}

func newPasswordSource(t *testing.T, h *pwCredentials) *Source {
	t.Helper()
	mux := http.NewServeMux()
	mux.Handle(credentialsv1connect.NewCredentialsServiceHandler(h))
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return &Source{
		credentials: credentialsv1connect.NewCredentialsServiceClient(server.Client(), server.URL),
		timeout:     5 * time.Second,
	}
}

func TestChangePasswordMapsTheDirectoryAnswer(t *testing.T) {
	for _, tc := range []struct {
		name  string
		resp  *credentialsv1.ChangePasswordResponse
		check func(t *testing.T, err error)
	}{
		{"ok", &credentialsv1.ChangePasswordResponse{Result: credentialsv1.VerifyResult_VERIFY_RESULT_OK}, func(t *testing.T, err error) { require.NoError(t, err) }},
		{"wrong old", &credentialsv1.ChangePasswordResponse{Result: credentialsv1.VerifyResult_VERIFY_RESULT_INVALID}, func(t *testing.T, err error) {
			require.ErrorIs(t, err, domain.ErrIncorrectPassword)
		}},
		{"locked", &credentialsv1.ChangePasswordResponse{Result: credentialsv1.VerifyResult_VERIFY_RESULT_LOCKED}, func(t *testing.T, err error) {
			require.ErrorIs(t, err, identity.ErrLocked)
		}},
		{"policy", &credentialsv1.ChangePasswordResponse{Result: credentialsv1.VerifyResult_VERIFY_RESULT_OK, PolicyViolations: []string{"too short"}}, func(t *testing.T, err error) {
			var pe *domain.PasswordPolicyError
			require.True(t, errors.As(err, &pe))
			require.Equal(t, []string{"too short"}, pe.Violations)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := newPasswordSource(t, &pwCredentials{change: tc.resp})
			tc.check(t, src.ChangePassword(context.Background(), "id-1", "old", "new"))
		})
	}
}

func TestCompleteForcedChange(t *testing.T) {
	f := &pwCredentials{}
	src := newPasswordSource(t, f)
	require.NoError(t, src.CompleteForcedChange(context.Background(), "id-1", "new"))
	require.Equal(t, "id-1", f.setReq.GetPrincipalId())
	require.Equal(t, "new", f.setReq.GetNewPassword())
	require.False(t, f.setReq.GetMustChange(), "the SSO never asks for another change")

	f.setErr = connect.NewError(connect.CodePermissionDenied, errors.New("no"))
	require.ErrorIs(t, src.CompleteForcedChange(context.Background(), "id-1", "new"), domain.ErrPasswordChangeNotAllowed)

	f.setErr, f.setViol = nil, []string{"reused"}
	var pe *domain.PasswordPolicyError
	require.True(t, errors.As(src.CompleteForcedChange(context.Background(), "id-1", "new"), &pe))
}
