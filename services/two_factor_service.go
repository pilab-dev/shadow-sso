package services

import (
	"context"
	"errors"
	"fmt"

	"connectrpc.com/connect"
	"github.com/pilab-dev/shadow-sso/domain"
	ssov1 "github.com/pilab-dev/shadow-sso/gen/proto/sso/v1"
	"github.com/pilab-dev/shadow-sso/gen/proto/sso/v1/ssov1connect"
	"github.com/pilab-dev/shadow-sso/internal/auth/totp" // The new TOTP utility
	"github.com/pilab-dev/shadow-sso/middleware"         // For GetAuthenticatedTokenFromContext
	"github.com/rs/zerolog/log"
	"google.golang.org/protobuf/types/known/emptypb"
)

// TwoFactorServer implements the ssov1connect.TwoFactorServiceHandler interface.
type TwoFactorServer struct {
	ssov1connect.UnimplementedTwoFactorServiceHandler // Embed for forward compatibility
	userRepo                                          domain.UserRepository
	passwordHasher                                    PasswordHasher // For verifying password in Disable2FA/GenerateRecoveryCodes
	ssoAppName                                        string         // Used as issuer in TOTP (e.g., "ShadowSSO")
	// secretEncrypter Decrypter // For encrypting/decrypting TOTP secret in DB (future)
}

// NewTwoFactorServer creates a new TwoFactorServer.
// ssoAppName is the name displayed in authenticator apps (TOTP issuer).
func NewTwoFactorServer(
	userRepo domain.UserRepository,
	hasher PasswordHasher,
	ssoAppName string,
) *TwoFactorServer {
	return &TwoFactorServer{
		userRepo:       userRepo,
		passwordHasher: hasher,
		ssoAppName:     ssoAppName,
	}
}

// InitiateTOTPSetup generates a new TOTP secret and QR code URI for the authenticated user.
func (s *TwoFactorServer) InitiateTOTPSetup(ctx context.Context, req *connect.Request[ssov1.InitiateTOTPSetupRequest]) (*connect.Response[ssov1.InitiateTOTPSetupResponse], error) {
	authedToken, ok := middleware.GetAuthenticatedTokenFromContext(ctx)
	if !ok || authedToken == nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("user not authenticated"))
	}

	user, err := s.userRepo.GetUserByID(ctx, authedToken.UserID)
	if err != nil {
		log.Error().Err(err).Str("userID", authedToken.UserID).Msg("InitiateTOTPSetup: User not found")
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("user not found: %w", err))
	}
	if user.IsTwoFactorEnabled {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("2FA is already enabled for this user"))
	}

	otpKey, otpAuthURI, err := totp.GenerateTOTPSecret(s.ssoAppName, user.Email)
	if err != nil {
		log.Error().Err(err).Msg("InitiateTOTPSetup: Failed to generate TOTP secret")
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("could not generate TOTP secret: %w", err))
	}

	user.TwoFactorSecret = otpKey.Secret() // Store base32 secret
	user.TwoFactorMethod = "TOTP"          // Tentatively set method
	// user.IsTwoFactorEnabled = false; // Stays false until verified

	if err := s.userRepo.UpdateUser(ctx, user); err != nil {
		log.Error().Err(err).Str("userID", user.ID).Msg("InitiateTOTPSetup: Failed to save temporary TOTP secret to user")
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to update user with new TOTP secret: %w", err))
	}

	resp := &ssov1.InitiateTOTPSetupResponse{
		Secret:    otpKey.Secret(), // Base32 encoded secret for manual entry
		QrCodeUri: otpAuthURI,
	}
	return connect.NewResponse(resp), nil
}

// VerifyAndEnableTOTP verifies a TOTP code and enables 2FA for the user.
func (s *TwoFactorServer) VerifyAndEnableTOTP(ctx context.Context, req *connect.Request[ssov1.VerifyAndEnableTOTPRequest]) (*connect.Response[ssov1.VerifyAndEnableTOTPResponse], error) {
	authedToken, ok := middleware.GetAuthenticatedTokenFromContext(ctx)
	if !ok || authedToken == nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("user not authenticated"))
	}
	user, err := s.userRepo.GetUserByID(ctx, authedToken.UserID)
	if err != nil {
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("user not found: %w", err))
	}
	if user.IsTwoFactorEnabled {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("2FA is already enabled"))
	}
	if user.TwoFactorSecret == "" || user.TwoFactorMethod != "TOTP" {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("TOTP setup not initiated or secret not found"))
	}

	valid, errValidate := totp.ValidateTOTPCode(user.TwoFactorSecret, req.Msg.TotpCode)
	if errValidate != nil {
		log.Error().Err(errValidate).Str("userID", user.ID).Msg("VerifyAndEnableTOTP: Error during TOTP code validation function")
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("error validating TOTP code: %w", errValidate))
	}
	if !valid {
		// TODO: Implement attempt counting / lockout for TOTP verification
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("invalid TOTP code"))
	}

	plaintextCodes, hashedCodes, err := totp.GenerateRecoveryCodes(totp.DefaultNumRecoveryCodes, totp.DefaultRecoveryCodeLength)
	if err != nil {
		log.Error().Err(err).Str("userID", user.ID).Msg("VerifyAndEnableTOTP: Failed to generate recovery codes")
		return nil, connect.NewError(connect.CodeInternal, errors.New("could not generate recovery codes"))
	}

	user.IsTwoFactorEnabled = true
	// user.TwoFactorMethod = "TOTP"; // Already set during initiate
	user.TwoFactorRecoveryCodes = hashedCodes // Store hashed recovery codes

	if err := s.userRepo.UpdateUser(ctx, user); err != nil {
		log.Error().Err(err).Str("userID", user.ID).Msg("VerifyAndEnableTOTP: Failed to update user to enable 2FA")
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to enable 2FA for user: %w", err))
	}

	resp := &ssov1.VerifyAndEnableTOTPResponse{
		RecoveryCodes: plaintextCodes, // Return plaintext codes ONCE
	}
	return connect.NewResponse(resp), nil
}

// Disable2FA disables 2FA for the authenticated user.
func (s *TwoFactorServer) Disable2FA(ctx context.Context, req *connect.Request[ssov1.Disable2FARequest]) (*connect.Response[emptypb.Empty], error) {
	authedToken, ok := middleware.GetAuthenticatedTokenFromContext(ctx)
	if !ok || authedToken == nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("user not authenticated"))
	}
	user, err := s.userRepo.GetUserByID(ctx, authedToken.UserID)
	if err != nil {
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("user not found: %w", err))
	}

	if !user.IsTwoFactorEnabled {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("2FA is not currently enabled for this user"))
	}
	if req.Msg.PasswordOr_2FaCode == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("password or 2FA code required to disable 2FA"))
	}

	// Verify password or current 2FA code
	passwordVerified := s.passwordHasher.Verify(user.PasswordHash, req.Msg.PasswordOr_2FaCode) == nil

	totpVerified := false
	if !passwordVerified && user.TwoFactorMethod == "TOTP" && user.TwoFactorSecret != "" {
		validTOTP, _ := totp.ValidateTOTPCode(user.TwoFactorSecret, req.Msg.PasswordOr_2FaCode)
		if validTOTP {
			totpVerified = true
		}
	}

	recoveryVerified := false
	usedRecoveryCodeIndex := -1
	if !passwordVerified && !totpVerified {
		validRecovery, idx := totp.VerifyRecoveryCode(user.TwoFactorRecoveryCodes, req.Msg.PasswordOr_2FaCode)
		if validRecovery {
			recoveryVerified = true
			usedRecoveryCodeIndex = idx
		}
	}

	if !passwordVerified && !totpVerified && !recoveryVerified {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("invalid password, TOTP code, or recovery code"))
	}

	user.IsTwoFactorEnabled = false
	user.TwoFactorMethod = "NONE"
	user.TwoFactorSecret = ""
	user.TwoFactorRecoveryCodes = []string{}

	if recoveryVerified { // If a recovery code was used, it should be invalidated
		if usedRecoveryCodeIndex >= 0 && usedRecoveryCodeIndex < len(user.TwoFactorRecoveryCodes) {
			// This line was causing issues, should be handled by service logic if needed
			// For Disable2FA, all recovery codes are cleared anyway.
		}
	}

	if err := s.userRepo.UpdateUser(ctx, user); err != nil {
		log.Error().Err(err).Str("userID", user.ID).Msg("Disable2FA: Failed to update user to disable 2FA")
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to disable 2FA: %w", err))
	}
	return connect.NewResponse(&emptypb.Empty{}), nil
}

// GenerateRecoveryCodes generates new recovery codes for a 2FA-enabled user.
func (s *TwoFactorServer) GenerateRecoveryCodes(ctx context.Context, req *connect.Request[ssov1.GenerateRecoveryCodesRequest]) (*connect.Response[ssov1.GenerateRecoveryCodesResponse], error) {
	authedToken, ok := middleware.GetAuthenticatedTokenFromContext(ctx)
	if !ok || authedToken == nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("user not authenticated"))
	}
	user, err := s.userRepo.GetUserByID(ctx, authedToken.UserID)
	if err != nil {
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("user not found: %w", err))
	}

	if !user.IsTwoFactorEnabled {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("2FA is not enabled for this user"))
	}

	if req.Msg.PasswordOr_2FaCode != "" {
		passwordVerified := s.passwordHasher.Verify(user.PasswordHash, req.Msg.PasswordOr_2FaCode) == nil
		totpVerified := false
		if !passwordVerified && user.TwoFactorMethod == "TOTP" && user.TwoFactorSecret != "" {
			validTOTP, _ := totp.ValidateTOTPCode(user.TwoFactorSecret, req.Msg.PasswordOr_2FaCode)
			if validTOTP {
				totpVerified = true
			}
		}
		// Typically, using a recovery code to generate new recovery codes is disallowed.
		if !passwordVerified && !totpVerified {
			return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("invalid password or TOTP code for re-authentication"))
		}
	} // Else, if PasswordOr_2FaCode is empty, proceed without re-auth (depends on policy)

	plaintextCodes, hashedCodes, err := totp.GenerateRecoveryCodes(totp.DefaultNumRecoveryCodes, totp.DefaultRecoveryCodeLength)
	if err != nil {
		log.Error().Err(err).Str("userID", user.ID).Msg("GenerateRecoveryCodes: Failed to generate new recovery codes")
		return nil, connect.NewError(connect.CodeInternal, errors.New("could not generate new recovery codes"))
	}
	user.TwoFactorRecoveryCodes = hashedCodes // Replace old codes

	if err := s.userRepo.UpdateUser(ctx, user); err != nil {
		log.Error().Err(err).Str("userID", user.ID).Msg("GenerateRecoveryCodes: Failed to save new recovery codes")
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to save new recovery codes: %w", err))
	}
	return connect.NewResponse(&ssov1.GenerateRecoveryCodesResponse{RecoveryCodes: plaintextCodes}), nil
}

// Ensure TwoFactorServer implements the handler interface (compile-time check)
var _ ssov1connect.TwoFactorServiceHandler = (*TwoFactorServer)(nil)
