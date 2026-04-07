package services

import (
	"context"
	"time"

	"github.com/pilab-dev/shadow-sso/domain"
	"github.com/pilab-dev/shadow-sso/internal/federation"
)

type defaultFederationService struct {
	fedService     *federation.Service
	userRepo       domain.UserRepository
	fedIDRepo      domain.UserFederatedIdentityRepository
	idpRepo        domain.IdPRepository
	tokenService   TokenService
	sessionRepo    domain.SessionRepository
	passwordHasher domain.PasswordHasher
}

func newFederationService(
	idpRepo domain.IdPRepository,
	userRepo domain.UserRepository,
	fedIDRepo domain.UserFederatedIdentityRepository,
	sessionRepo domain.SessionRepository,
	tokenService TokenService,
	passwordHasher domain.PasswordHasher,
	issuer string,
) FederationService {
	fedSvc := federation.NewService(idpRepo, issuer)
	return &defaultFederationService{
		fedService:     fedSvc,
		userRepo:       userRepo,
		fedIDRepo:      fedIDRepo,
		idpRepo:        idpRepo,
		tokenService:   tokenService,
		sessionRepo:    sessionRepo,
		passwordHasher: passwordHasher,
	}
}

func (s *defaultFederationService) InitiateFederatedLogin(ctx context.Context, providerName string) (authURL, state string, err error) {
	state, err = s.fedService.GenerateAuthState()
	if err != nil {
		return "", "", err
	}
	authURL, err = s.fedService.GetAuthorizationURL(ctx, providerName, state)
	if err != nil {
		return "", "", err
	}
	return authURL, state, nil
}

func (s *defaultFederationService) HandleFederatedCallback(ctx context.Context, providerName, state, sessionState, code string) (*FederationCallbackResult, error) {
	externalUser, _, err := s.fedService.HandleCallback(ctx, providerName, state, sessionState, code)
	if err != nil {
		return nil, err
	}

	providerConfig, err := s.idpRepo.GetIdPByName(ctx, providerName)
	if err != nil || providerConfig == nil {
		return nil, domain.ErrClientNotFound
	}

	fedIdentity, err := s.fedIDRepo.GetByProviderUserID(ctx, providerName, externalUser.ProviderUserID)
	if err == nil && fedIdentity != nil {
		localUser, userErr := s.userRepo.GetUserByID(ctx, fedIdentity.UserID)
		if userErr != nil {
			return nil, userErr
		}
		return s.completeFederationLogin(ctx, localUser, FederationStatusLoginSuccessful, "Login successful.")
	}

	newUser := &domain.User{
		Email:        externalUser.Email,
		FirstName:    externalUser.FirstName,
		LastName:     externalUser.LastName,
		Status:       domain.UserStatusActive,
		PasswordHash: "",
	}
	if err := s.userRepo.CreateUser(ctx, newUser); err != nil {
		return nil, err
	}

	newLink := &domain.UserFederatedIdentity{
		UserID:           newUser.ID,
		ProviderID:       providerConfig.ID,
		ProviderUserID:   externalUser.ProviderUserID,
		ProviderEmail:    externalUser.Email,
		ProviderUsername: externalUser.Username,
	}
	if err := s.fedIDRepo.Create(ctx, newLink); err != nil {
		return nil, err
	}

	return s.completeFederationLogin(ctx, newUser, FederationStatusLoginSuccessful, "Account created and login successful.")
}

func (s *defaultFederationService) completeFederationLogin(ctx context.Context, user *domain.User, status FederationCallbackStatus, message string) (*FederationCallbackResult, error) {
	tokenPair, err := s.tokenService.GenerateTokenPair(ctx, "sso-default-client", user.ID, "openid profile email offline_access", 1*time.Hour)
	if err != nil {
		return nil, err
	}

	session := &domain.Session{
		UserID:       user.ID,
		RefreshToken: tokenPair.RefreshToken,
		ExpiresAt:    time.Now().Add(30 * 24 * time.Hour),
	}
	_ = s.sessionRepo.StoreSession(ctx, session)

	now := time.Now()
	user.LastLoginAt = &now
	user.FailedLoginAttempts = 0
	_ = s.userRepo.UpdateUser(ctx, user)

	return &FederationCallbackResult{
		Status:       status,
		Message:      message,
		AccessToken:  tokenPair.AccessToken,
		TokenType:    tokenPair.TokenType,
		ExpiresIn:    int32(tokenPair.ExpiresIn),
		RefreshToken: tokenPair.RefreshToken,
		UserInfo:     user,
	}, nil
}

func (s *defaultFederationService) ListUserFederatedIdentities(ctx context.Context, userID string) ([]*domain.UserFederatedIdentity, error) {
	return s.fedIDRepo.ListByUserID(ctx, userID)
}

func (s *defaultFederationService) RemoveUserFederatedIdentity(ctx context.Context, userID, providerName, providerUserID string) error {
	fedIdentity, err := s.fedIDRepo.GetByProviderUserID(ctx, providerName, providerUserID)
	if err != nil {
		return err
	}
	if fedIdentity.UserID != userID {
		return domain.ErrInvalidCredentials
	}
	return s.fedIDRepo.Delete(ctx, fedIdentity.ID)
}

func (s *defaultFederationService) PromptMergeFederatedAccount(ctx context.Context, continuationToken string) (*MergePromptResult, error) {
	return &MergePromptResult{
		Message:      "Merge functionality requires continuation token handling.",
		ProviderName: continuationToken,
	}, nil
}

func (s *defaultFederationService) ConfirmMergeFederatedAccount(ctx context.Context, continuationToken string) (*FederationCallbackResult, error) {
	return nil, domain.ErrFlowNotFound
}

func (s *defaultFederationService) Stop() {}

func (s *defaultFederationService) AuthenticateDirect(ctx context.Context, providerName, username, password string) (interface{}, error) {
	return s.fedService.AuthenticateDirect(ctx, providerName, username, password)
}
