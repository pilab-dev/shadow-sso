package services

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/pilab-dev/shadow-sso/domain"
	ssov1 "github.com/pilab-dev/shadow-sso/gen/sso/v1"
	"github.com/pilab-dev/shadow-sso/internal/auth/totp" // Direct use of totp utils
	"github.com/pilab-dev/shadow-sso/middleware"       // For AuthenticatedTokenContextKey
	"github.com/pilab-dev/shadow-sso/ssso"             // For ssso.Token for context
	"github.com/pquerna/otp"                           // For otp.Key, if needed directly
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	// "google.golang.org/protobuf/types/known/emptypb"
	// "google.golang.org/protobuf/types/known/timestamppb"
)

// --- Mock Implementations ---

type MockUserRepository struct {
	mock.Mock
}

func (m *MockUserRepository) CreateUser(ctx context.Context, user *domain.User) error {
	args := m.Called(ctx, user); return args.Error(0)
}
func (m *MockUserRepository) GetUserByID(ctx context.Context, id string) (*domain.User, error) {
	args := m.Called(ctx, id); if args.Get(0) == nil { return nil, args.Error(1) }; return args.Get(0).(*domain.User), args.Error(1)
}
func (m *MockUserRepository) GetUserByEmail(ctx context.Context, email string) (*domain.User, error) {
	args := m.Called(ctx, email); if args.Get(0) == nil { return nil, args.Error(1) }; return args.Get(0).(*domain.User), args.Error(1)
}
func (m *MockUserRepository) UpdateUser(ctx context.Context, user *domain.User) error {
	args := m.Called(ctx, user); return args.Error(0)
}
func (m *MockUserRepository) DeleteUser(ctx context.Context, id string) error {
	args := m.Called(ctx, id); return args.Error(0)
}
func (m *MockUserRepository) ListUsers(ctx context.Context, pageToken string, pageSize int) ([]*domain.User, string, error) {
	args := m.Called(ctx, pageToken, pageSize); if args.Get(0) == nil { return nil, args.String(1), args.Error(2) }; return args.Get(0).([]*domain.User), args.String(1), args.Error(2)
}

type MockPasswordHasher struct {
	mock.Mock
}

func (m *MockPasswordHasher) Hash(password string) (string, error) {
	args := m.Called(password); return args.String(0), args.Error(1)
}
func (m *MockPasswordHasher) Verify(hashedPassword, password string) error {
	args := m.Called(hashedPassword, password); return args.Error(0)
}


// --- TwoFactorServer Tests ---
const testAppNameForTOTP = "TestSSOApp"

func TestTwoFactorServer_InitiateTOTPSetup(t *testing.T) {
	authedUserID := "user-for-2fa-setup"
	authedUserEmail := "user2fa@example.com"
	authedToken := &ssso.Token{UserID: authedUserID}
	ctxWithAuth := context.WithValue(context.Background(), middleware.AuthenticatedTokenContextKey, authedToken)

	t.Run("Successful Initiate TOTP Setup", func(t *testing.T) {
		mockUserRepo := new(MockUserRepository)
		service := NewTwoFactorServer(mockUserRepo, nil, testAppNameForTOTP)
		user := &domain.User{ID: authedUserID, Email: authedUserEmail, IsTwoFactorEnabled: false}

		mockUserRepo.On("GetUserByID", ctxWithAuth, authedUserID).Return(user, nil).Once()
		mockUserRepo.On("UpdateUser", ctxWithAuth, mock.MatchedBy(func(u *domain.User) bool {
			return u.ID == authedUserID && u.TwoFactorSecret != "" && u.TwoFactorMethod == "TOTP" && !u.IsTwoFactorEnabled
		})).Return(nil).Once()

		req := connect.NewRequest(&ssov1.InitiateTOTPSetupRequest{})
		resp, err := service.InitiateTOTPSetup(ctxWithAuth, req)

		require.NoError(t, err)
		require.NotNil(t, resp); require.NotNil(t, resp.Msg)
		assert.NotEmpty(t, resp.Msg.Secret, "TOTP secret should be returned")
		assert.Contains(t, resp.Msg.QrCodeUri, "otpauth://totp/"+testAppNameForTOTP+":"+authedUserEmail, "QR Code URI should be correct")
		mockUserRepo.AssertExpectations(t)
	})

	t.Run("Initiate TOTP - User Not Found", func(t *testing.T) {
		mockUserRepo := new(MockUserRepository)
		service := NewTwoFactorServer(mockUserRepo, nil, testAppNameForTOTP)
		mockUserRepo.On("GetUserByID", ctxWithAuth, authedUserID).Return(nil, errors.New("user not found")).Once()

		req := connect.NewRequest(&ssov1.InitiateTOTPSetupRequest{})
		_, err := service.InitiateTOTPSetup(ctxWithAuth, req)
		require.Error(t, err)
		connectErr, _ := err.(*connect.Error)
		assert.Equal(t, connect.CodeNotFound, connectErr.Code())
		mockUserRepo.AssertExpectations(t)
	})

	t.Run("Initiate TOTP - Already Enabled", func(t *testing.T) {
		mockUserRepo := new(MockUserRepository)
		service := NewTwoFactorServer(mockUserRepo, nil, testAppNameForTOTP)
		user := &domain.User{ID: authedUserID, Email: authedUserEmail, IsTwoFactorEnabled: true}
		mockUserRepo.On("GetUserByID", ctxWithAuth, authedUserID).Return(user, nil).Once()

		req := connect.NewRequest(&ssov1.InitiateTOTPSetupRequest{})
		_, err := service.InitiateTOTPSetup(ctxWithAuth, req)
		require.Error(t, err)
		connectErr, _ := err.(*connect.Error)
		assert.Equal(t, connect.CodeFailedPrecondition, connectErr.Code())
		mockUserRepo.AssertExpectations(t)
	})

	t.Run("Initiate TOTP - UpdateUser Fails", func(t *testing.T) {
		mockUserRepo := new(MockUserRepository)
		service := NewTwoFactorServer(mockUserRepo, nil, testAppNameForTOTP)
		user := &domain.User{ID: authedUserID, Email: authedUserEmail, IsTwoFactorEnabled: false}
		mockUserRepo.On("GetUserByID", ctxWithAuth, authedUserID).Return(user, nil).Once()
		mockUserRepo.On("UpdateUser", ctxWithAuth, mock.AnythingOfType("*domain.User")).Return(errors.New("db update failed")).Once()

		req := connect.NewRequest(&ssov1.InitiateTOTPSetupRequest{})
		_, err := service.InitiateTOTPSetup(ctxWithAuth, req)
		require.Error(t, err)
		connectErr, _ := err.(*connect.Error)
		assert.Equal(t, connect.CodeInternal, connectErr.Code())
		mockUserRepo.AssertExpectations(t)
	})
}

func TestTwoFactorServer_VerifyAndEnableTOTP(t *testing.T) {
	authedUserID := "user-verify-2fa"
	authedToken := &ssso.Token{UserID: authedUserID}
	ctxWithAuth := context.WithValue(context.Background(), middleware.AuthenticatedTokenContextKey, authedToken)

	// Generate a real secret for validation testing
	// Use pquerna/otp directly for key generation to get a valid secret for testing
	otpKey, errKey := otp.Generate(otp.GenerateOpts{Issuer: testAppNameForTOTP, AccountName: "user@example.com"})
	require.NoError(t, errKey)
	validSecret := otpKey.Secret()
	validCode, errCode := totp.GenerateCode(validSecret, time.Now())
	require.NoError(t, errCode)

	t.Run("Successful Verify and Enable", func(t *testing.T) {
		mockUserRepo := new(MockUserRepository)
		service := NewTwoFactorServer(mockUserRepo, nil, testAppNameForTOTP)
		user := &domain.User{ID: authedUserID, IsTwoFactorEnabled: false, TwoFactorSecret: validSecret, TwoFactorMethod: "TOTP"}

		mockUserRepo.On("GetUserByID", ctxWithAuth, authedUserID).Return(user, nil).Once()
		mockUserRepo.On("UpdateUser", ctxWithAuth, mock.MatchedBy(func(u *domain.User) bool {
			return u.ID == authedUserID && u.IsTwoFactorEnabled == true && u.TwoFactorMethod == "TOTP" && len(u.TwoFactorRecoveryCodes) == totp.DefaultNumRecoveryCodes
		})).Return(nil).Once()

		req := connect.NewRequest(&ssov1.VerifyAndEnableTOTPRequest{TotpCode: validCode})
		resp, err := service.VerifyAndEnableTOTP(ctxWithAuth, req)

		require.NoError(t, err)
		require.NotNil(t, resp); require.NotNil(t, resp.Msg)
		assert.Len(t, resp.Msg.RecoveryCodes, totp.DefaultNumRecoveryCodes)
		mockUserRepo.AssertExpectations(t)
	})

	t.Run("Verify - Invalid TOTP Code", func(t *testing.T) {
		mockUserRepo := new(MockUserRepository)
		service := NewTwoFactorServer(mockUserRepo, nil, testAppNameForTOTP)
		user := &domain.User{ID: authedUserID, IsTwoFactorEnabled: false, TwoFactorSecret: validSecret, TwoFactorMethod: "TOTP"}
		mockUserRepo.On("GetUserByID", ctxWithAuth, authedUserID).Return(user, nil).Once()

		req := connect.NewRequest(&ssov1.VerifyAndEnableTOTPRequest{TotpCode: "invalid123"})
		_, err := service.VerifyAndEnableTOTP(ctxWithAuth, req)
		require.Error(t, err)
		connectErr, _ := err.(*connect.Error)
		assert.Equal(t, connect.CodeInvalidArgument, connectErr.Code())
		mockUserRepo.AssertExpectations(t)
		mockUserRepo.AssertNotCalled(t, "UpdateUser", mock.Anything, mock.Anything)
	})
	// Add more tests: UserNotFound, AlreadyEnabled, NoSecret (not initiated), UpdateUserFails
}

func TestTwoFactorServer_Disable2FA(t *testing.T) {
	authedUserID := "user-disable-2fa"
	userPassword := "password123"
	userHashedPassword := "hashedPassword123"
	authedToken := &ssso.Token{UserID: authedUserID}
	ctxWithAuth := context.WithValue(context.Background(), middleware.AuthenticatedTokenContextKey, authedToken)

	otpKeyDisable, _ := otp.Generate(otp.GenerateOpts{Issuer: testAppNameForTOTP, AccountName: "user@example.com"})
	userSecretForDisable := otpKeyDisable.Secret()
	validTOTPCodeForDisable, _ := totp.GenerateCode(userSecretForDisable, time.Now())

	t.Run("Successful Disable with Password", func(t *testing.T) {
		mockUserRepo := new(MockUserRepository)
		mockHasher := new(MockPasswordHasher)
		service := NewTwoFactorServer(mockUserRepo, mockHasher, testAppNameForTOTP)
		user := &domain.User{
			ID: authedUserID, IsTwoFactorEnabled: true, TwoFactorMethod: "TOTP",
			TwoFactorSecret: "someSecret", PasswordHash: userHashedPassword,
		}
		mockUserRepo.On("GetUserByID", ctxWithAuth, authedUserID).Return(user, nil).Once()
		mockHasher.On("Verify", userHashedPassword, userPassword).Return(nil).Once()
		mockUserRepo.On("UpdateUser", ctxWithAuth, mock.MatchedBy(func(u *domain.User) bool {
			return u.ID == authedUserID && !u.IsTwoFactorEnabled && u.TwoFactorMethod == "NONE" && u.TwoFactorSecret == "" && len(u.TwoFactorRecoveryCodes) == 0
		})).Return(nil).Once()

		req := connect.NewRequest(&ssov1.Disable2FARequest{PasswordOr_2FaCode: userPassword})
		_, err := service.Disable2FA(ctxWithAuth, req)
		require.NoError(t, err)
		mockUserRepo.AssertExpectations(t)
		mockHasher.AssertExpectations(t)
	})

	t.Run("Successful Disable with TOTP Code", func(t *testing.T) {
		mockUserRepo := new(MockUserRepository)
		mockHasher := new(MockPasswordHasher)
		service := NewTwoFactorServer(mockUserRepo, mockHasher, testAppNameForTOTP)
		user := &domain.User{
			ID: authedUserID, IsTwoFactorEnabled: true, TwoFactorMethod: "TOTP",
			TwoFactorSecret: userSecretForDisable, PasswordHash: userHashedPassword,
		}
		mockUserRepo.On("GetUserByID", ctxWithAuth, authedUserID).Return(user, nil).Once()
		mockHasher.On("Verify", userHashedPassword, validTOTPCodeForDisable).Return(errors.New("mismatch")).Once()
		mockUserRepo.On("UpdateUser", ctxWithAuth, mock.AnythingOfType("*domain.User")).Return(nil).Once()

		req := connect.NewRequest(&ssov1.Disable2FARequest{PasswordOr_2FaCode: validTOTPCodeForDisable})
		_, err := service.Disable2FA(ctxWithAuth, req)
		require.NoError(t, err)
		mockUserRepo.AssertExpectations(t)
		mockHasher.AssertExpectations(t)
	})
}

// And more failure cases for Disable2FA (e.g. invalid code, 2FA not enabled, etc.)
// And more failure cases for VerifyAndEnableTOTP (e.g. user not found, already enabled, etc.)

	t.Run("Successful Disable with Recovery Code", func(t *testing.T) {
		mockUserRepo := new(MockUserRepository)
		mockHasher := new(MockPasswordHasher)
		service := NewTwoFactorServer(mockUserRepo, mockHasher, testAppNameForTOTP)

		plaintextRecoveryCode := "recovery123abc"
		hashedKnownRecoveryCode, _ := bcrypt.GenerateFromPassword([]byte(plaintextRecoveryCode), bcrypt.DefaultCost)

		user := &domain.User{
			ID: authedUserID, IsTwoFactorEnabled: true, TwoFactorMethod: "TOTP",
			PasswordHash: userHashedPassword,
			TwoFactorSecret: userSecretForDisable,
			TwoFactorRecoveryCodes: []string{string(hashedKnownRecoveryCode), "some_other_hashed_code"},
		}
		mockUserRepo.On("GetUserByID", ctxWithAuth, authedUserID).Return(user, nil).Once()
		mockHasher.On("Verify", userHashedPassword, plaintextRecoveryCode).Return(errors.New("mismatch")).Once()
		// TOTP verify will fail (as plaintextRecoveryCode is not a TOTP code for userSecretForDisable)
		// Then Recovery code verify will succeed
		mockUserRepo.On("UpdateUser", ctxWithAuth, mock.MatchedBy(func(u *domain.User) bool {
			// Check that the used recovery code was removed
			return u.ID == authedUserID && !u.IsTwoFactorEnabled && len(u.TwoFactorRecoveryCodes) == 1
		})).Return(nil).Once()


		req := connect.NewRequest(&ssov1.Disable2FARequest{PasswordOr_2FaCode: plaintextRecoveryCode})
		_, err := service.Disable2FA(ctxWithAuth, req)
		require.NoError(t, err)
		mockUserRepo.AssertExpectations(t)
		mockHasher.AssertExpectations(t)
	})

	t.Run("Disable 2FA - All Auth Methods Fail", func(t *testing.T) {
		mockUserRepo := new(MockUserRepository)
		mockHasher := new(MockPasswordHasher)
		service := NewTwoFactorServer(mockUserRepo, mockHasher, testAppNameForTOTP)
		user := &domain.User{
			ID: authedUserID, IsTwoFactorEnabled: true, TwoFactorMethod: "TOTP",
			PasswordHash: userHashedPassword, TwoFactorSecret: userSecretForDisable,
			TwoFactorRecoveryCodes: []string{"hashed_code1"},
		}
		invalidCode := "completelyInvalidCode"
		mockUserRepo.On("GetUserByID", ctxWithAuth, authedUserID).Return(user, nil).Once()
		mockHasher.On("Verify", userHashedPassword, invalidCode).Return(errors.New("mismatch")).Once()
		// TOTP will fail, Recovery will fail

		req := connect.NewRequest(&ssov1.Disable2FARequest{PasswordOr_2FaCode: invalidCode})
		_, err := service.Disable2FA(ctxWithAuth, req)
		require.Error(t, err)
		connectErr, _ := err.(*connect.Error)
		assert.Equal(t, connect.CodeUnauthenticated, connectErr.Code())
		assert.Contains(t, connectErr.Message(), "invalid password, TOTP code, or recovery code")
		mockUserRepo.AssertExpectations(t)
		mockHasher.AssertExpectations(t)
	})

	t.Run("Disable 2FA - Not Enabled", func(t *testing.T) {
		mockUserRepo := new(MockUserRepository)
        mockHasher := new(MockPasswordHasher)
		service := NewTwoFactorServer(mockUserRepo, mockHasher, testAppNameForTOTP)
		user := &domain.User{ID: authedUserID, IsTwoFactorEnabled: false}
		mockUserRepo.On("GetUserByID", ctxWithAuth, authedUserID).Return(user, nil).Once()

		req := connect.NewRequest(&ssov1.Disable2FARequest{PasswordOr_2FaCode: "anycode"})
		_, err := service.Disable2FA(ctxWithAuth, req)
		require.Error(t, err)
		connectErr, _ := err.(*connect.Error)
		assert.Equal(t, connect.CodeFailedPrecondition, connectErr.Code())
		mockUserRepo.AssertExpectations(t)
	})
}

func TestTwoFactorServer_GenerateRecoveryCodes(t *testing.T) {
	authedUserID := "user-gen-recovery"
	authedToken := &ssso.Token{UserID: authedUserID}
	ctxWithAuth := context.WithValue(context.Background(), middleware.AuthenticatedTokenContextKey, authedToken)
	userPassword := "password123"
	userHashedPassword := "hashedPassword123"

	t.Run("Successful GenerateRecoveryCodes_NoReAuth", func(t *testing.T) {
		mockUserRepo := new(MockUserRepository)
		mockHasher := new(MockPasswordHasher)
		service := NewTwoFactorServer(mockUserRepo, mockHasher, testAppNameForTOTP)
		user := &domain.User{ID: authedUserID, IsTwoFactorEnabled: true, TwoFactorMethod: "TOTP"}

		mockUserRepo.On("GetUserByID", ctxWithAuth, authedUserID).Return(user, nil).Once()
		mockUserRepo.On("UpdateUser", ctxWithAuth, mock.MatchedBy(func(u *domain.User) bool {
			return u.ID == authedUserID && len(u.TwoFactorRecoveryCodes) == totp.DefaultNumRecoveryCodes && u.TwoFactorRecoveryCodes[0] != ""
		})).Return(nil).Once()

		req := connect.NewRequest(&ssov1.GenerateRecoveryCodesRequest{PasswordOr_2FaCode: ""})
		resp, err := service.GenerateRecoveryCodes(ctxWithAuth, req)

		require.NoError(t, err)
		require.NotNil(t, resp); require.NotNil(t, resp.Msg)
		assert.Len(t, resp.Msg.RecoveryCodes, totp.DefaultNumRecoveryCodes)
		mockUserRepo.AssertExpectations(t)
	})

    t.Run("Successful GenerateRecoveryCodes_WithPasswordReAuth", func(t *testing.T) {
        mockUserRepo := new(MockUserRepository)
        mockHasher := new(MockPasswordHasher)
	    service := NewTwoFactorServer(mockUserRepo, mockHasher, testAppNameForTOTP)
        user := &domain.User{
            ID: authedUserID, IsTwoFactorEnabled: true, TwoFactorMethod: "TOTP", PasswordHash: userHashedPassword,
        }
        mockUserRepo.On("GetUserByID", ctxWithAuth, authedUserID).Return(user, nil).Once()
        mockHasher.On("Verify", userHashedPassword, userPassword).Return(nil).Once()
        mockUserRepo.On("UpdateUser", ctxWithAuth, mock.AnythingOfType("*domain.User")).Return(nil).Once()


        req := connect.NewRequest(&ssov1.GenerateRecoveryCodesRequest{PasswordOr_2FaCode: userPassword})
        resp, err := service.GenerateRecoveryCodes(ctxWithAuth, req)
        require.NoError(t, err)
        assert.Len(t, resp.Msg.RecoveryCodes, totp.DefaultNumRecoveryCodes)
        mockUserRepo.AssertExpectations(t)
        mockHasher.AssertExpectations(t)
    })

    t.Run("GenerateRecoveryCodes_2FANotEnabled", func(t *testing.T) {
        mockUserRepo := new(MockUserRepository)
        mockHasher := new(MockPasswordHasher)
	    service := NewTwoFactorServer(mockUserRepo, mockHasher, testAppNameForTOTP)
        user := &domain.User{ID: authedUserID, IsTwoFactorEnabled: false}
        mockUserRepo.On("GetUserByID", ctxWithAuth, authedUserID).Return(user, nil).Once()

        req := connect.NewRequest(&ssov1.GenerateRecoveryCodesRequest{})
        _, err := service.GenerateRecoveryCodes(ctxWithAuth, req)
        require.Error(t, err)
        connectErr, _ := err.(*connect.Error)
        assert.Equal(t, connect.CodeFailedPrecondition, connectErr.Code())
        mockUserRepo.AssertExpectations(t)
    })

    t.Run("GenerateRecoveryCodes_ReAuthFails", func(t *testing.T) {
        mockUserRepo := new(MockUserRepository)
        mockHasher := new(MockPasswordHasher)
	    service := NewTwoFactorServer(mockUserRepo, mockHasher, testAppNameForTOTP)
        user := &domain.User{
            ID: authedUserID, IsTwoFactorEnabled: true, TwoFactorMethod: "TOTP", PasswordHash: userHashedPassword,
            TwoFactorSecret: "a-totp-secret", // For TOTP attempt after password fail
        }
        mockUserRepo.On("GetUserByID", ctxWithAuth, authedUserID).Return(user, nil).Once()
        mockHasher.On("Verify", userHashedPassword, "wrongPassword_or_badTOTP").Return(errors.New("mismatch")).Once()
        // Service will then try TOTP which will also fail as "wrongPassword_or_badTOTP" is not a valid TOTP code for "a-totp-secret"

        req := connect.NewRequest(&ssov1.GenerateRecoveryCodesRequest{PasswordOr_2FaCode: "wrongPassword_or_badTOTP"})
        _, err := service.GenerateRecoveryCodes(ctxWithAuth, req)
        require.Error(t, err)
        connectErr, _ := err.(*connect.Error)
        assert.Equal(t, connect.CodeUnauthenticated, connectErr.Code())
        mockUserRepo.AssertExpectations(t)
        mockHasher.AssertExpectations(t)
    })
    // TODO: Add tests for UserNotFound, UpdateUserFails for GenerateRecoveryCodes
}
