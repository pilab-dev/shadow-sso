package services

import (
	"context"

	"github.com/pilab-dev/shadow-sso/client"
	"github.com/pilab-dev/shadow-sso/domain"
	"github.com/pilab-dev/shadow-sso/internal/auth/totp"
)

type defaultClientService struct {
	clientRepo domain.ClientRepository
}

func newClientService(clientRepo domain.ClientRepository) ClientService {
	return &defaultClientService{clientRepo: clientRepo}
}

func (s *defaultClientService) CreateConfidentialClient(ctx context.Context, name string, redirectURIs []string, allowedScopes []string) (*domain.Client, error) {
	cs := client.NewClientService(s.clientRepo)
	return cs.CreateConfidentialClient(ctx, name, redirectURIs, allowedScopes)
}

func (s *defaultClientService) CreatePublicClient(ctx context.Context, name string, redirectURIs []string, allowedScopes []string) (*domain.Client, error) {
	cs := client.NewClientService(s.clientRepo)
	return cs.CreatePublicClient(ctx, name, redirectURIs, allowedScopes)
}

func (s *defaultClientService) CreateClient(ctx context.Context, c *domain.Client) (*domain.Client, error) {
	if err := s.clientRepo.CreateClient(ctx, c); err != nil {
		return nil, err
	}
	return c, nil
}

func (s *defaultClientService) ValidateRedirectURI(ctx context.Context, clientID, redirectURI string) error {
	cs := client.NewClientService(s.clientRepo)
	return cs.ValidateRedirectURI(ctx, clientID, redirectURI)
}

func (s *defaultClientService) ValidateScope(ctx context.Context, clientID string, requestedScopes []string) error {
	cs := client.NewClientService(s.clientRepo)
	return cs.ValidateScope(ctx, clientID, requestedScopes)
}

func (s *defaultClientService) ValidateGrantType(ctx context.Context, clientID, grantType string) error {
	cs := client.NewClientService(s.clientRepo)
	return cs.ValidateGrantType(ctx, clientID, grantType)
}

func (s *defaultClientService) RequiresPKCE(ctx context.Context, clientID string) (bool, error) {
	cs := client.NewClientService(s.clientRepo)
	return cs.RequiresPKCE(ctx, clientID)
}

func (s *defaultClientService) GetClient(ctx context.Context, clientID string) (*domain.Client, error) {
	return s.clientRepo.GetClient(ctx, clientID)
}

func (s *defaultClientService) ValidateClient(ctx context.Context, clientID, clientSecret string) (*domain.Client, error) {
	return s.clientRepo.ValidateClient(ctx, clientID, clientSecret)
}

type defaultUserService struct {
	userRepo                 domain.UserRepository
	passwordHasher           domain.PasswordHasher
	phoneVerificationService PhoneVerificationService
}

func newUserService(userRepo domain.UserRepository, hasher domain.PasswordHasher, phoneVerificationService PhoneVerificationService) UserService {
	return &defaultUserService{
		userRepo:                 userRepo,
		passwordHasher:           hasher,
		phoneVerificationService: phoneVerificationService,
	}
}

func (s *defaultUserService) RegisterUser(ctx context.Context, email, password, firstName, lastName string) (*domain.User, error) {
	hashedPassword, err := s.passwordHasher.Hash(password)
	if err != nil {
		return nil, err
	}
	newUser := &domain.User{
		Email:        email,
		PasswordHash: hashedPassword,
		FirstName:    firstName,
		LastName:     lastName,
		Status:       domain.UserStatusPending,
		Roles:        []string{"user"},
	}
	if err := s.userRepo.CreateUser(ctx, newUser); err != nil {
		return nil, err
	}
	return newUser, nil
}

func (s *defaultUserService) ActivateUser(ctx context.Context, userID string) error {
	user, err := s.userRepo.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}
	if user.Status == domain.UserStatusActive {
		return nil
	}
	user.Status = domain.UserStatusActive
	return s.userRepo.UpdateUser(ctx, user)
}

func (s *defaultUserService) LockUser(ctx context.Context, userID string) error {
	user, err := s.userRepo.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}
	if user.Status == domain.UserStatusLocked {
		return nil
	}
	user.Status = domain.UserStatusLocked
	return s.userRepo.UpdateUser(ctx, user)
}

func (s *defaultUserService) ListUsers(ctx context.Context, pageToken string, pageSize int) ([]*domain.User, string, error) {
	return s.userRepo.ListUsers(ctx, pageToken, pageSize)
}

func (s *defaultUserService) GetUser(ctx context.Context, userID string) (*domain.User, error) {
	return s.userRepo.GetUserByID(ctx, userID)
}

func (s *defaultUserService) ChangePassword(ctx context.Context, userID, oldPassword, newPassword string) error {
	user, err := s.userRepo.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}
	if err := s.passwordHasher.Verify(user.PasswordHash, oldPassword); err != nil {
		return err
	}
	hashedPassword, err := s.passwordHasher.Hash(newPassword)
	if err != nil {
		return err
	}
	user.PasswordHash = hashedPassword
	return s.userRepo.UpdateUser(ctx, user)
}

func (s *defaultUserService) SendPhoneVerificationOtp(ctx context.Context, userID string) error {
	return s.phoneVerificationService.SendVerificationOTP(ctx, userID)
}

func (s *defaultUserService) VerifyPhoneNumber(ctx context.Context, userID, otp string) error {
	return s.phoneVerificationService.VerifyPhoneNumber(ctx, userID, otp)
}

type defaultTwoFactorService struct {
	userRepo       domain.UserRepository
	passwordHasher domain.PasswordHasher
	mfaService     MFAService
	pushMFAService PushMFAService
	ssoAppName     string
}

func newTwoFactorService(
	userRepo domain.UserRepository,
	hasher domain.PasswordHasher,
	mfaService MFAService,
	pushMFAService PushMFAService,
	ssoAppName string,
) TwoFactorService {
	return &defaultTwoFactorService{
		userRepo:       userRepo,
		passwordHasher: hasher,
		mfaService:     mfaService,
		pushMFAService: pushMFAService,
		ssoAppName:     ssoAppName,
	}
}

func (s *defaultTwoFactorService) InitiateTOTPSetup(ctx context.Context, userID string) (secret, qrCodeURI string, err error) {
	user, err := s.userRepo.GetUserByID(ctx, userID)
	if err != nil {
		return "", "", err
	}
	if user.IsTwoFactorEnabled {
		return "", "", domain.ErrInvalidConfig
	}
	otpKey, otpAuthURI, err := totp.GenerateTOTPSecret(s.ssoAppName, user.Email)
	if err != nil {
		return "", "", err
	}
	user.TwoFactorSecret = otpKey.Secret()
	user.TwoFactorMethod = "TOTP"
	if err := s.userRepo.UpdateUser(ctx, user); err != nil {
		return "", "", err
	}
	return otpKey.Secret(), otpAuthURI, nil
}

func (s *defaultTwoFactorService) VerifyAndEnableTOTP(ctx context.Context, userID, totpCode string) (recoveryCodes []string, err error) {
	user, err := s.userRepo.GetUserByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	if user.IsTwoFactorEnabled {
		return nil, domain.ErrInvalidConfig
	}
	if user.TwoFactorSecret == "" || user.TwoFactorMethod != "TOTP" {
		return nil, domain.ErrInvalidConfig
	}
	valid, errValidate := totp.ValidateTOTPCode(user.TwoFactorSecret, totpCode)
	if errValidate != nil {
		return nil, errValidate
	}
	if !valid {
		return nil, domain.ErrInvalidCredentials
	}
	plaintextCodes, hashedCodes, err := totp.GenerateRecoveryCodes(totp.DefaultNumRecoveryCodes, totp.DefaultRecoveryCodeLength)
	if err != nil {
		return nil, err
	}
	user.IsTwoFactorEnabled = true
	user.TwoFactorRecoveryCodes = hashedCodes
	if err := s.userRepo.UpdateUser(ctx, user); err != nil {
		return nil, err
	}
	return plaintextCodes, nil
}

func (s *defaultTwoFactorService) Disable2FA(ctx context.Context, userID, passwordOr2FaCode string) error {
	user, err := s.userRepo.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}
	if !user.IsTwoFactorEnabled {
		return domain.ErrInvalidConfig
	}
	passwordVerified := s.passwordHasher.Verify(user.PasswordHash, passwordOr2FaCode) == nil
	totpVerified := false
	if !passwordVerified && user.TwoFactorMethod == "TOTP" && user.TwoFactorSecret != "" {
		validTOTP, _ := totp.ValidateTOTPCode(user.TwoFactorSecret, passwordOr2FaCode)
		totpVerified = validTOTP
	}
	if !passwordVerified && !totpVerified {
		return domain.ErrInvalidCredentials
	}
	user.IsTwoFactorEnabled = false
	user.TwoFactorMethod = "NONE"
	user.TwoFactorSecret = ""
	user.TwoFactorRecoveryCodes = []string{}
	return s.userRepo.UpdateUser(ctx, user)
}

func (s *defaultTwoFactorService) GenerateRecoveryCodes(ctx context.Context, userID, passwordOr2FaCode string) (recoveryCodes []string, err error) {
	user, err := s.userRepo.GetUserByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	if !user.IsTwoFactorEnabled {
		return nil, domain.ErrInvalidConfig
	}
	if passwordOr2FaCode != "" {
		passwordVerified := s.passwordHasher.Verify(user.PasswordHash, passwordOr2FaCode) == nil
		totpVerified := false
		if !passwordVerified && user.TwoFactorMethod == "TOTP" && user.TwoFactorSecret != "" {
			validTOTP, _ := totp.ValidateTOTPCode(user.TwoFactorSecret, passwordOr2FaCode)
			totpVerified = validTOTP
		}
		if !passwordVerified && !totpVerified {
			return nil, domain.ErrInvalidCredentials
		}
	}
	plaintextCodes, hashedCodes, err := totp.GenerateRecoveryCodes(totp.DefaultNumRecoveryCodes, totp.DefaultRecoveryCodeLength)
	if err != nil {
		return nil, err
	}
	user.TwoFactorRecoveryCodes = hashedCodes
	if err := s.userRepo.UpdateUser(ctx, user); err != nil {
		return nil, err
	}
	return plaintextCodes, nil
}

func (s *defaultTwoFactorService) InitiateHOTPSetup(ctx context.Context, userID string) (secret, qrCodeURI string, initialCounter uint64, err error) {
	user, err := s.userRepo.GetUserByID(ctx, userID)
	if err != nil {
		return "", "", 0, err
	}
	if user.IsTwoFactorEnabled {
		return "", "", 0, domain.ErrInvalidConfig
	}
	otpKey, otpAuthURI, err := totp.GenerateHOTPSecret(s.ssoAppName, user.Email)
	if err != nil {
		return "", "", 0, err
	}
	user.TwoFactorSecret = otpKey.Secret()
	user.TwoFactorMethod = "HOTP"
	user.EmailMFAOTPCounter = 0
	if err := s.userRepo.UpdateUser(ctx, user); err != nil {
		return "", "", 0, err
	}
	return otpKey.Secret(), otpAuthURI, 0, nil
}

func (s *defaultTwoFactorService) VerifyAndEnableHOTP(ctx context.Context, userID, hotpCode string) (recoveryCodes []string, err error) {
	user, err := s.userRepo.GetUserByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	if user.IsTwoFactorEnabled {
		return nil, domain.ErrInvalidConfig
	}
	if user.TwoFactorSecret == "" || user.TwoFactorMethod != "HOTP" {
		return nil, domain.ErrInvalidConfig
	}
	valid, errValidate := totp.ValidateHOTPCode(user.TwoFactorSecret, hotpCode, user.EmailMFAOTPCounter)
	if errValidate != nil {
		return nil, errValidate
	}
	if !valid {
		return nil, domain.ErrInvalidCredentials
	}
	plaintextCodes, hashedCodes, err := totp.GenerateRecoveryCodes(totp.DefaultNumRecoveryCodes, totp.DefaultRecoveryCodeLength)
	if err != nil {
		return nil, err
	}
	user.IsTwoFactorEnabled = true
	user.TwoFactorRecoveryCodes = hashedCodes
	user.EmailMFAOTPCounter++
	if err := s.userRepo.UpdateUser(ctx, user); err != nil {
		return nil, err
	}
	return plaintextCodes, nil
}

func (s *defaultTwoFactorService) InitiateEmailMFASetup(ctx context.Context, userID string) error {
	return s.mfaService.InitiateEmailMFASetup(ctx, userID)
}

func (s *defaultTwoFactorService) VerifyAndEnableEmailMFA(ctx context.Context, userID, emailOtp string) (recoveryCodes []string, err error) {
	err = s.mfaService.VerifyAndEnableEmailMFA(ctx, userID, emailOtp)
	if err != nil {
		return nil, err
	}
	plaintextCodes, _, err := totp.GenerateRecoveryCodes(totp.DefaultNumRecoveryCodes, totp.DefaultRecoveryCodeLength)
	if err != nil {
		return nil, err
	}
	return plaintextCodes, nil
}

func (s *defaultTwoFactorService) SendMFAChallenge(ctx context.Context, userID string) (method string, counter uint64, challengeID string, err error) {
	return s.mfaService.SendMFAChallenge(ctx, userID)
}

func (s *defaultTwoFactorService) VerifyMFAChallenge(ctx context.Context, userID, code string, counter uint64) (bool, error) {
	return s.mfaService.VerifyMFAChallenge(ctx, userID, code, counter)
}

func (s *defaultTwoFactorService) InitiatePushMFASetup(ctx context.Context, userID, deviceToken string) error {
	return s.pushMFAService.RegisterDeviceToken(ctx, userID, deviceToken)
}

func (s *defaultTwoFactorService) VerifyAndEnablePushMFA(ctx context.Context, userID string) (recoveryCodes []string, err error) {
	err = s.pushMFAService.EnablePushMFA(ctx, userID)
	if err != nil {
		return nil, err
	}
	user, err := s.userRepo.GetUserByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	user.IsTwoFactorEnabled = true
	user.TwoFactorMethod = "PUSH"
	if err := s.userRepo.UpdateUser(ctx, user); err != nil {
		return nil, err
	}
	plaintextCodes, _, err := totp.GenerateRecoveryCodes(totp.DefaultNumRecoveryCodes, totp.DefaultRecoveryCodeLength)
	if err != nil {
		return nil, err
	}
	return plaintextCodes, nil
}

func (s *defaultTwoFactorService) RegisterPushDevice(ctx context.Context, userID, deviceToken string) error {
	return s.pushMFAService.RegisterDeviceToken(ctx, userID, deviceToken)
}

func (s *defaultTwoFactorService) UnregisterPushDevice(ctx context.Context, userID, deviceToken string) error {
	return s.pushMFAService.UnregisterDeviceToken(ctx, userID, deviceToken)
}

func (s *defaultTwoFactorService) RespondToPushChallenge(ctx context.Context, userID, challengeID, response string) (status string, err error) {
	approved := response == "approve" || response == "approved"
	err = s.pushMFAService.VerifyPushMFAChallenge(ctx, userID, challengeID, approved)
	if err != nil {
		return "", err
	}
	if approved {
		return "approved", nil
	}
	return "denied", nil
}

func (s *defaultTwoFactorService) GetPushChallengeStatus(ctx context.Context, userID, challengeID string) (status string, err error) {
	return s.pushMFAService.GetPushMFAChallengeStatus(ctx, userID, challengeID)
}
