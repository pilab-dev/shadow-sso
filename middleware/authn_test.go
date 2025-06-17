package middleware

import (
	"context"
	"errors"
	"net/http"
	// "net/http/httptest" // Not used for direct Authenticator test
	"testing"
	"time"

	"connectrpc.com/authn"
	"connectrpc.com/connect"
	"github.com/pilab-dev/shadow-sso/ssso" // For ssso.TokenService, ssso.Token, ssso.ErrTokenExpiredOrRevoked
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// MockTokenService for authn interceptor tests
type MockTokenService struct {
	mock.Mock
}

func (m *MockTokenService) ValidateAccessToken(ctx context.Context, tokenValue string) (*ssso.Token, error) {
	args := m.Called(ctx, tokenValue)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*ssso.Token), args.Error(1)
}

// MockAuthnRequest for testing Authenticator directly
type MockAuthnRequest struct {
	mock.Mock
}

func (m *MockAuthnRequest) Header() http.Header {
	args := m.Called()
	return args.Get(0).(http.Header)
}
func (m *MockAuthnRequest) Spec() connect.Spec {
	args := m.Called()
	// Return a zero value connect.Spec, or a mocked one if its fields are accessed.
	// Authenticator does not currently use Spec, so zero value is fine.
	return connect.Spec{}
}
func (m *MockAuthnRequest) Peer() connect.Peer {
	args := m.Called()
	return args.Get(0).(connect.Peer)
}
func (m *MockAuthnRequest) SendMethod() string {
	args := m.Called()
	return args.String(0)
}
func (m *MockAuthnRequest) Type() connect.StreamType {
	args := m.Called()
	return args.Get(0).(connect.StreamType)
}
func (m *MockAuthnRequest) IsClient() bool {
	args := m.Called()
	return args.Bool(0)
}


func TestAuthInterceptor_AuthenticatorLogic(t *testing.T) {
	validTokenString := "valid.bearer.token"
	validSssoToken := &ssso.Token{
		ID:        "test-jti",
		UserID:    "user123",
		Issuer:    "sso-issuer",
		Scope:     "read",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	testCases := []struct {
		name                string
		authHeader          string
		mockSetup           func(mockTS *MockTokenService) // Setup for mockTokenService for this case
		expectAuthSuccess   bool                          // Whether we expect authentication to succeed
		expectedConnectCode connect.Code                  // Expected Connect error code if error and error is connect.Error
		expectedErrorIs     error                         // Expected error type if not connect.Error (e.g. authn.ErrNoCredentials)
	}{
		{
			name:       "Successful Authentication",
			authHeader: "Bearer " + validTokenString,
			mockSetup: func(mockTS *MockTokenService) {
				mockTS.On("ValidateAccessToken", mock.Anything, validTokenString).Return(validSssoToken, nil).Once()
			},
			expectAuthSuccess: true,
		},
		{
			name:              "No Authorization Header",
			authHeader:        "",
			mockSetup:         func(mockTS *MockTokenService) {}, // No call to TokenService expected
			expectAuthSuccess: false,
			expectedErrorIs:   authn.ErrNoCredentials,
		},
		{
			name:              "Malformed Authorization Header - No Bearer",
			authHeader:        "Basic somecredentials",
			mockSetup:         func(mockTS *MockTokenService) {},
			expectAuthSuccess: false,
			expectedConnectCode: connect.CodeUnauthenticated,
		},
		{
			name:              "Malformed Authorization Header - Bearer No Token",
			authHeader:        "Bearer ",
			mockSetup:         func(mockTS *MockTokenService) {},
			expectAuthSuccess: false,
			expectedConnectCode: connect.CodeUnauthenticated,
		},
		{
			name:       "TokenService Validation Fails - ExpiredOrRevoked",
			authHeader: "Bearer " + validTokenString,
			mockSetup: func(mockTS *MockTokenService) {
				mockTS.On("ValidateAccessToken", mock.Anything, validTokenString).Return(nil, ssso.ErrTokenExpiredOrRevoked).Once()
			},
			expectAuthSuccess: false,
			expectedConnectCode: connect.CodeUnauthenticated,
		},
		{
			name:       "TokenService Validation Fails - Other Error",
			authHeader: "Bearer " + validTokenString,
			mockSetup: func(mockTS *MockTokenService) {
				mockTS.On("ValidateAccessToken", mock.Anything, validTokenString).Return(nil, errors.New("some other validation error")).Once()
			},
			expectAuthSuccess: false,
			expectedConnectCode: connect.CodeUnauthenticated,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockTokenService := new(MockTokenService)
			tc.mockSetup(mockTokenService)

			authenticator := NewAuthenticator(mockTokenService) // Get the authenticator instance

			mockAuthnReq := new(MockAuthnRequest)
			header := http.Header{}
			if tc.authHeader != "" {
				header.Set("Authorization", tc.authHeader)
			}
			mockAuthnReq.On("Header").Return(header).Maybe() // Maybe because if authHeader is empty, it might not be checked by some paths
			// Spec() is not used by current Authenticator, so no need to mock specific return for it unless it changes.
			// mockAuthnReq.On("Spec").Return(connect.Spec{}).Maybe()


			claims, err := authenticator.Authenticate(context.Background(), mockAuthnReq)

			if tc.expectAuthSuccess {
				assert.NoError(t, err)
				require.NotNil(t, claims)
				assert.Equal(t, validSssoToken.UserID, claims.Get("sub"))
				internalToken, ok := claims.Get(internalTokenClaimKey).(*ssso.Token)
				require.True(t, ok)
				assert.Equal(t, validSssoToken.ID, internalToken.ID)
			} else {
				assert.Error(t, err)
				assert.Nil(t, claims)
				if tc.expectedErrorIs != nil {
					assert.ErrorIs(t, err, tc.expectedErrorIs)
				} else { // Expect a connect.Error
					connectErr, ok := err.(*connect.Error)
					require.True(t, ok, "Error should be a connect.Error type")
					assert.Equal(t, tc.expectedConnectCode, connectErr.Code(), "Connect error code mismatch")
				}
			}
			mockTokenService.AssertExpectations(t)
			mockAuthnReq.AssertExpectations(t)
		})
	}
}
