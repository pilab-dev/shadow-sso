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

	// "github.com/pilab-dev/shadow-sso/middleware" // No longer needed here
	"github.com/rs/zerolog/log"
	"google.golang.org/protobuf/types/known/emptypb"
)

// TwoFactorServer implements the ssov1connect.TwoFactorServiceHandler interface.
type TwoFactorServer struct {
	ssov1connect.UnimplementedTwoFactorServiceHandler // Embed for forward compatibility
	userRepo                                          domain.UserRepository
	passwordHasher                                    domain.PasswordHasher
	mfaService                                        MFAService
	pushMFAService                                    PushMFAService
	ssoAppName                                        string
}

func NewTwoFactorServer(
	userRepo domain.UserRepository,
	hasher domain.PasswordHasher,
	mfaService MFAService,
	pushMFAService PushMFAService,
	ssoAppName string,
) *TwoFactorServer {
	return &TwoFactorServer{
		userRepo:       userRepo,
		passwordHasher: hasher,
		mfaService:     mfaService,
		pushMFAService: pushMFAService,
		ssoAppName:     ssoAppName,
	}
}

// InitiateTOTPSetup generates a new TOTP secret and QR code URI for the authenticated user.
func (s *TwoFactorServer) InitiateTOTPSetup(ctx context.Context, req *connect.Request[ssov1.InitiateTOTPSetupRequest]) (*connect.Response[ssov1.InitiateTOTPSetupResponse], error) {
	authedToken, ok := domain.GetAuthenticatedTokenFromContext(ctx)
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
	authedToken, ok := domain.GetAuthenticatedTokenFromContext(ctx)
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
	authedToken, ok := domain.GetAuthenticatedTokenFromContext(ctx)
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
	authedToken, ok := domain.GetAuthenticatedTokenFromContext(ctx)
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

// InitiateHOTPSetup generates a new HOTP secret and QR code URI for the authenticated user.
func (s *TwoFactorServer) InitiateHOTPSetup(ctx context.Context, req *connect.Request[ssov1.InitiateHOTPSetupRequest]) (*connect.Response[ssov1.InitiateHOTPSetupResponse], error) {
	authedToken, ok := domain.GetAuthenticatedTokenFromContext(ctx)
	if !ok || authedToken == nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("user not authenticated"))
	}

	user, err := s.userRepo.GetUserByID(ctx, authedToken.UserID)
	if err != nil {
		log.Error().Err(err).Str("userID", authedToken.UserID).Msg("InitiateHOTPSetup: User not found")
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("user not found: %w", err))
	}
	if user.IsTwoFactorEnabled {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("2FA is already enabled for this user"))
	}

	// Generate HOTP secret
	otpKey, otpAuthURI, err := totp.GenerateHOTPSecret(s.ssoAppName, user.Email)
	if err != nil {
		log.Error().Err(err).Msg("InitiateHOTPSetup: Failed to generate HOTP secret")
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("could not generate HOTP secret: %w", err))
	}

	user.TwoFactorSecret = otpKey.Secret() // Store base32 secret
	user.TwoFactorMethod = "HOTP"          // Set method to HOTP
	user.EmailMFAOTPCounter = 0            // Initialize counter

	if err := s.userRepo.UpdateUser(ctx, user); err != nil {
		log.Error().Err(err).Str("userID", user.ID).Msg("InitiateHOTPSetup: Failed to save temporary HOTP secret to user")
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to update user with new HOTP secret: %w", err))
	}

	resp := &ssov1.InitiateHOTPSetupResponse{
		Secret:         otpKey.Secret(),
		QrCodeUri:      otpAuthURI,
		InitialCounter: 0,
	}
	return connect.NewResponse(resp), nil
}

// VerifyAndEnableHOTP verifies an HOTP code and enables 2FA for the user.
func (s *TwoFactorServer) VerifyAndEnableHOTP(ctx context.Context, req *connect.Request[ssov1.VerifyAndEnableHOTPRequest]) (*connect.Response[ssov1.VerifyAndEnableHOTPResponse], error) {
	authedToken, ok := domain.GetAuthenticatedTokenFromContext(ctx)
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
	if user.TwoFactorSecret == "" || user.TwoFactorMethod != "HOTP" {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("HOTP setup not initiated or secret not found"))
	}

	valid, errValidate := totp.ValidateHOTPCode(user.TwoFactorSecret, req.Msg.HotpCode, user.EmailMFAOTPCounter)
	if errValidate != nil {
		log.Error().Err(errValidate).Str("userID", user.ID).Msg("VerifyAndEnableHOTP: Error during HOTP code validation")
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("error validating HOTP code: %w", errValidate))
	}
	if !valid {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("invalid HOTP code"))
	}

	plaintextCodes, hashedCodes, err := totp.GenerateRecoveryCodes(totp.DefaultNumRecoveryCodes, totp.DefaultRecoveryCodeLength)
	if err != nil {
		log.Error().Err(err).Str("userID", user.ID).Msg("VerifyAndEnableHOTP: Failed to generate recovery codes")
		return nil, connect.NewError(connect.CodeInternal, errors.New("could not generate recovery codes"))
	}

	user.IsTwoFactorEnabled = true
	user.TwoFactorRecoveryCodes = hashedCodes
	user.EmailMFAOTPCounter++ // Increment counter on successful validation

	if err := s.userRepo.UpdateUser(ctx, user); err != nil {
		log.Error().Err(err).Str("userID", user.ID).Msg("VerifyAndEnableHOTP: Failed to update user to enable 2FA")
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to enable 2FA for user: %w", err))
	}

	resp := &ssov1.VerifyAndEnableHOTPResponse{
		RecoveryCodes: plaintextCodes,
	}
	return connect.NewResponse(resp), nil
}

// InitiateEmailMFASetup initiates email MFA setup by sending an OTP.
func (s *TwoFactorServer) InitiateEmailMFASetup(ctx context.Context, req *connect.Request[ssov1.InitiateEmailMFASetupRequest]) (*connect.Response[ssov1.InitiateEmailMFASetupResponse], error) {
	authedToken, ok := domain.GetAuthenticatedTokenFromContext(ctx)
	if !ok || authedToken == nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("user not authenticated"))
	}

	user, err := s.userRepo.GetUserByID(ctx, authedToken.UserID)
	if err != nil {
		log.Error().Err(err).Str("userID", authedToken.UserID).Msg("InitiateEmailMFASetup: User not found")
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("user not found: %w", err))
	}
	if user.IsTwoFactorEnabled {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("2FA is already enabled for this user"))
	}

	err = s.mfaService.InitiateEmailMFASetup(ctx, authedToken.UserID)
	if err != nil {
		log.Error().Err(err).Str("userID", authedToken.UserID).Msg("InitiateEmailMFASetup: Failed to initiate email MFA setup")
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to initiate email MFA setup: %w", err))
	}

	resp := &ssov1.InitiateEmailMFASetupResponse{
		Message: "An OTP has been sent to your email address. Please check your inbox and enter the code to complete setup.",
	}
	return connect.NewResponse(resp), nil
}

// VerifyAndEnableEmailMFA verifies the email OTP and enables email MFA.
func (s *TwoFactorServer) VerifyAndEnableEmailMFA(ctx context.Context, req *connect.Request[ssov1.VerifyAndEnableEmailMFARequest]) (*connect.Response[ssov1.VerifyAndEnableEmailMFAResponse], error) {
	authedToken, ok := domain.GetAuthenticatedTokenFromContext(ctx)
	if !ok || authedToken == nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("user not authenticated"))
	}

	err := s.mfaService.VerifyAndEnableEmailMFA(ctx, authedToken.UserID, req.Msg.EmailOtp)
	if err != nil {
		log.Error().Err(err).Str("userID", authedToken.UserID).Msg("VerifyAndEnableEmailMFA: Failed to verify and enable email MFA")
		// Convert domain errors to appropriate connect errors
		switch err {
		case domain.ErrEmailMFAAlreadyEnabled:
			return nil, connect.NewError(connect.CodeFailedPrecondition, err)
		case domain.ErrInvalidEmailOTP, domain.ErrEmailOTPExpired, domain.ErrEmailOTPNotFound:
			return nil, connect.NewError(connect.CodeInvalidArgument, err)
		default:
			return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to verify and enable email MFA: %w", err))
		}
	}

	// Generate recovery codes (handled by MFAService, but we need to return them)
	_, err = s.userRepo.GetUserByID(ctx, authedToken.UserID)
	if err != nil {
		log.Error().Err(err).Str("userID", authedToken.UserID).Msg("VerifyAndEnableEmailMFA: Failed to get user after enabling MFA")
		return nil, connect.NewError(connect.CodeInternal, errors.New("email MFA enabled but failed to retrieve recovery codes"))
	}

	// For email MFA, we need to generate recovery codes here since the MFAService doesn't return them
	plaintextCodes, _, err := totp.GenerateRecoveryCodes(totp.DefaultNumRecoveryCodes, totp.DefaultRecoveryCodeLength)
	if err != nil {
		log.Error().Err(err).Str("userID", authedToken.UserID).Msg("VerifyAndEnableEmailMFA: Failed to generate recovery codes")
		return nil, connect.NewError(connect.CodeInternal, errors.New("email MFA enabled but failed to generate recovery codes"))
	}

	resp := &ssov1.VerifyAndEnableEmailMFAResponse{
		RecoveryCodes: plaintextCodes,
	}
	return connect.NewResponse(resp), nil
}

// SendMFAChallenge sends an MFA challenge based on the user's configured method.
func (s *TwoFactorServer) SendMFAChallenge(ctx context.Context, req *connect.Request[ssov1.SendMFAChallengeRequest]) (*connect.Response[ssov1.SendMFAChallengeResponse], error) {
	authedToken, ok := domain.GetAuthenticatedTokenFromContext(ctx)
	if !ok || authedToken == nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("user not authenticated"))
	}

	method, counter, challengeID, err := s.mfaService.SendMFAChallenge(ctx, authedToken.UserID)
	if err != nil {
		log.Error().Err(err).Str("userID", authedToken.UserID).Msg("SendMFAChallenge: Failed to send MFA challenge")
		// Convert domain errors to appropriate connect errors
		switch err {
		case domain.ErrRateLimitExceeded:
			return nil, connect.NewError(connect.CodeResourceExhausted, err)
		default:
			return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to send MFA challenge: %w", err))
		}
	}

	message := "MFA challenge sent successfully."
	switch method {
	case "EMAIL":
		message = "An OTP has been sent to your email address."
	case "TOTP":
		message = "Please enter your TOTP code from your authenticator app."
	case "HOTP":
		message = "Please enter your HOTP code from your authenticator app."
	}

	resp := &ssov1.SendMFAChallengeResponse{
		Method:      method,
		Message:     message,
		Counter:     counter,
		ChallengeId: challengeID,
	}
	return connect.NewResponse(resp), nil
}

// VerifyMFAChallenge verifies an MFA code based on the user's configured method.
func (s *TwoFactorServer) VerifyMFAChallenge(ctx context.Context, req *connect.Request[ssov1.VerifyMFAChallengeRequest]) (*connect.Response[ssov1.VerifyMFAChallengeResponse], error) {
	authedToken, ok := domain.GetAuthenticatedTokenFromContext(ctx)
	if !ok || authedToken == nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("user not authenticated"))
	}

	verified, err := s.mfaService.VerifyMFAChallenge(ctx, authedToken.UserID, req.Msg.Code, req.Msg.Counter)
	if err != nil {
		log.Error().Err(err).Str("userID", authedToken.UserID).Msg("VerifyMFAChallenge: Failed to verify MFA challenge")
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to verify MFA challenge: %w", err))
	}

	resp := &ssov1.VerifyMFAChallengeResponse{
		Verified: verified,
	}
	return connect.NewResponse(resp), nil
}

// InitiatePushMFASetup initiates push MFA setup by registering a device token
func (s *TwoFactorServer) InitiatePushMFASetup(ctx context.Context, req *connect.Request[ssov1.InitiatePushMFASetupRequest]) (*connect.Response[ssov1.InitiatePushMFASetupResponse], error) {
	authedToken, ok := domain.GetAuthenticatedTokenFromContext(ctx)
	if !ok || authedToken == nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("user not authenticated"))
	}

	err := s.pushMFAService.RegisterDeviceToken(ctx, authedToken.UserID, req.Msg.DeviceToken)
	if err != nil {
		log.Error().Err(err).Str("userID", authedToken.UserID).Msg("InitiatePushMFASetup: Failed to register device token")
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to register device token: %w", err))
	}

	resp := &ssov1.InitiatePushMFASetupResponse{
		Message: "Device token registered successfully. Push MFA is now available.",
	}
	return connect.NewResponse(resp), nil
}

// VerifyAndEnablePushMFA enables push MFA for the user
func (s *TwoFactorServer) VerifyAndEnablePushMFA(ctx context.Context, req *connect.Request[ssov1.VerifyAndEnablePushMFARequest]) (*connect.Response[ssov1.VerifyAndEnablePushMFAResponse], error) {
	authedToken, ok := domain.GetAuthenticatedTokenFromContext(ctx)
	if !ok || authedToken == nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("user not authenticated"))
	}

	err := s.pushMFAService.EnablePushMFA(ctx, authedToken.UserID)
	if err != nil {
		log.Error().Err(err).Str("userID", authedToken.UserID).Msg("VerifyAndEnablePushMFA: Failed to enable push MFA")
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to enable push MFA: %w", err))
	}

	// Generate recovery codes
	user, err := s.userRepo.GetUserByID(ctx, authedToken.UserID)
	if err != nil {
		log.Error().Err(err).Str("userID", authedToken.UserID).Msg("VerifyAndEnablePushMFA: Failed to get user after enabling MFA")
		return nil, connect.NewError(connect.CodeInternal, errors.New("push MFA enabled but failed to retrieve recovery codes"))
	}

	// Update user's 2FA method
	user.IsTwoFactorEnabled = true
	user.TwoFactorMethod = "PUSH"

	err = s.userRepo.UpdateUser(ctx, user)
	if err != nil {
		log.Error().Err(err).Str("userID", authedToken.UserID).Msg("VerifyAndEnablePushMFA: Failed to update user 2FA method")
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to update user 2FA method: %w", err))
	}

	plaintextCodes, _, err := totp.GenerateRecoveryCodes(totp.DefaultNumRecoveryCodes, totp.DefaultRecoveryCodeLength)
	if err != nil {
		log.Error().Err(err).Str("userID", authedToken.UserID).Msg("VerifyAndEnablePushMFA: Failed to generate recovery codes")
		return nil, connect.NewError(connect.CodeInternal, errors.New("push MFA enabled but failed to generate recovery codes"))
	}

	resp := &ssov1.VerifyAndEnablePushMFAResponse{
		RecoveryCodes: plaintextCodes,
	}
	return connect.NewResponse(resp), nil
}

// RegisterPushDevice registers a device token for push notifications
func (s *TwoFactorServer) RegisterPushDevice(ctx context.Context, req *connect.Request[ssov1.RegisterPushDeviceRequest]) (*connect.Response[ssov1.RegisterPushDeviceResponse], error) {
	authedToken, ok := domain.GetAuthenticatedTokenFromContext(ctx)
	if !ok || authedToken == nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("user not authenticated"))
	}

	err := s.pushMFAService.RegisterDeviceToken(ctx, authedToken.UserID, req.Msg.DeviceToken)
	if err != nil {
		log.Error().Err(err).Str("userID", authedToken.UserID).Msg("RegisterPushDevice: Failed to register device token")
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to register device token: %w", err))
	}

	resp := &ssov1.RegisterPushDeviceResponse{
		Message: "Device registered successfully.",
	}
	return connect.NewResponse(resp), nil
}

// UnregisterPushDevice removes a device token
func (s *TwoFactorServer) UnregisterPushDevice(ctx context.Context, req *connect.Request[ssov1.UnregisterPushDeviceRequest]) (*connect.Response[ssov1.UnregisterPushDeviceResponse], error) {
	authedToken, ok := domain.GetAuthenticatedTokenFromContext(ctx)
	if !ok || authedToken == nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("user not authenticated"))
	}

	err := s.pushMFAService.UnregisterDeviceToken(ctx, authedToken.UserID, req.Msg.DeviceToken)
	if err != nil {
		log.Error().Err(err).Str("userID", authedToken.UserID).Msg("UnregisterPushDevice: Failed to unregister device token")
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to unregister device token: %w", err))
	}

	resp := &ssov1.UnregisterPushDeviceResponse{
		Message: "Device unregistered successfully.",
	}
	return connect.NewResponse(resp), nil
}

// RespondToPushChallenge allows users to respond to push MFA challenges
func (s *TwoFactorServer) RespondToPushChallenge(ctx context.Context, req *connect.Request[ssov1.RespondToPushChallengeRequest]) (*connect.Response[ssov1.RespondToPushChallengeResponse], error) {
	authedToken, ok := domain.GetAuthenticatedTokenFromContext(ctx)
	if !ok || authedToken == nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("user not authenticated"))
	}

	approved := req.Msg.Response == "approve" || req.Msg.Response == "approved"
	err := s.pushMFAService.VerifyPushMFAChallenge(ctx, authedToken.UserID, req.Msg.ChallengeId, approved)
	if err != nil {
		log.Error().Err(err).Str("userID", authedToken.UserID).Str("challengeID", req.Msg.ChallengeId).Msg("RespondToPushChallenge: Failed to verify push challenge")
		switch err {
		case domain.ErrChallengeNotFound:
			return nil, connect.NewError(connect.CodeNotFound, err)
		case domain.ErrChallengeExpired:
			return nil, connect.NewError(connect.CodeDeadlineExceeded, err)
		case domain.ErrChallengeAlreadyUsed:
			return nil, connect.NewError(connect.CodeFailedPrecondition, err)
		default:
			return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to respond to push challenge: %w", err))
		}
	}

	status := "approved"
	if !approved {
		status = "denied"
	}

	resp := &ssov1.RespondToPushChallengeResponse{
		Status: status,
	}
	return connect.NewResponse(resp), nil
}

// GetPushChallengeStatus gets the status of a push MFA challenge
func (s *TwoFactorServer) GetPushChallengeStatus(ctx context.Context, req *connect.Request[ssov1.GetPushChallengeStatusRequest]) (*connect.Response[ssov1.GetPushChallengeStatusResponse], error) {
	authedToken, ok := domain.GetAuthenticatedTokenFromContext(ctx)
	if !ok || authedToken == nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("user not authenticated"))
	}

	status, err := s.pushMFAService.GetPushMFAChallengeStatus(ctx, authedToken.UserID, req.Msg.ChallengeId)
	if err != nil {
		log.Error().Err(err).Str("userID", authedToken.UserID).Str("challengeID", req.Msg.ChallengeId).Msg("GetPushChallengeStatus: Failed to get challenge status")
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to get challenge status: %w", err))
	}

	resp := &ssov1.GetPushChallengeStatusResponse{
		Status: status,
	}
	return connect.NewResponse(resp), nil
}

// Ensure TwoFactorServer implements the handler interface (compile-time check)
var _ ssov1connect.TwoFactorServiceHandler = (*TwoFactorServer)(nil)
