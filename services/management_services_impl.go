package services

import (
	"context"
	"crypto/rand"
	"crypto/rsa"

	"github.com/pilab-dev/shadow-sso/domain"
)

type defaultIDPManagementService struct {
	idpRepo domain.IdPRepository
}

func newIDPManagementService(idpRepo domain.IdPRepository) IDPManagementService {
	return &defaultIDPManagementService{idpRepo: idpRepo}
}

func (s *defaultIDPManagementService) AddIdP(ctx context.Context, idp *domain.IdentityProvider) (*domain.IdentityProvider, error) {
	if err := s.idpRepo.AddIdP(ctx, idp); err != nil {
		return nil, err
	}
	return idp, nil
}

func (s *defaultIDPManagementService) GetIdP(ctx context.Context, id string) (*domain.IdentityProvider, error) {
	return s.idpRepo.GetIdPByID(ctx, id)
}

func (s *defaultIDPManagementService) ListIdPs(ctx context.Context, onlyEnabled bool) ([]*domain.IdentityProvider, error) {
	return s.idpRepo.ListIdPs(ctx, onlyEnabled)
}

func (s *defaultIDPManagementService) UpdateIdP(ctx context.Context, idp *domain.IdentityProvider) (*domain.IdentityProvider, error) {
	if err := s.idpRepo.UpdateIdP(ctx, idp); err != nil {
		return nil, err
	}
	return idp, nil
}

func (s *defaultIDPManagementService) DeleteIdP(ctx context.Context, id string) error {
	return s.idpRepo.DeleteIdP(ctx, id)
}

type defaultClientManagementService struct {
	clientRepo   domain.ClientRepository
	secretHasher domain.PasswordHasher
}

func newClientManagementService(clientRepo domain.ClientRepository, hasher domain.PasswordHasher) ClientManagementService {
	return &defaultClientManagementService{clientRepo: clientRepo, secretHasher: hasher}
}

func (s *defaultClientManagementService) RegisterClient(ctx context.Context, c *domain.Client) (*domain.Client, string, error) {
	plaintextSecret := ""
	if c.Type == domain.ClientTypeConfidential {
		plaintextSecret = c.Secret
		hashed, err := s.secretHasher.Hash(c.Secret)
		if err != nil {
			return nil, "", err
		}
		c.Secret = hashed
	}
	if err := s.clientRepo.CreateClient(ctx, c); err != nil {
		return nil, "", err
	}
	return c, plaintextSecret, nil
}

func (s *defaultClientManagementService) GetClient(ctx context.Context, clientID string) (*domain.Client, error) {
	return s.clientRepo.GetClient(ctx, clientID)
}

func (s *defaultClientManagementService) ListClients(ctx context.Context, filter domain.ClientFilter) ([]*domain.Client, string, error) {
	clients, err := s.clientRepo.ListClients(ctx, filter)
	return clients, "", err
}

func (s *defaultClientManagementService) UpdateClient(ctx context.Context, c *domain.Client) (*domain.Client, error) {
	if err := s.clientRepo.UpdateClient(ctx, c); err != nil {
		return nil, err
	}
	return c, nil
}

func (s *defaultClientManagementService) DeleteClient(ctx context.Context, clientID string) error {
	return s.clientRepo.DeleteClient(ctx, clientID)
}

type defaultSAKeyGenerator struct{}

func (g *defaultSAKeyGenerator) GenerateRSAKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

type defaultServiceAccountService struct {
	keyGen     SAKeyGenerator
	saRepo     domain.ServiceAccountRepository
	pubKeyRepo domain.PublicKeyRepository
}

func newServiceAccountService(keyGen SAKeyGenerator, saRepo domain.ServiceAccountRepository, pubKeyRepo domain.PublicKeyRepository) ServiceAccountService {
	return &defaultServiceAccountService{keyGen: keyGen, saRepo: saRepo, pubKeyRepo: pubKeyRepo}
}

func (s *defaultServiceAccountService) CreateServiceAccountKey(ctx context.Context, projectID, clientEmail, displayName string) (*domain.ServiceAccount, *domain.ServiceAccountKey, error) {
	return nil, nil, nil
}

func (s *defaultServiceAccountService) ListServiceAccountKeys(ctx context.Context, serviceAccountID string) ([]*domain.PublicKeyInfo, error) {
	return nil, nil
}

func (s *defaultServiceAccountService) DeleteServiceAccountKey(ctx context.Context, serviceAccountID, keyID string) error {
	return nil
}
