package mfa

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"time"

	"github.com/google/uuid"
	"github.com/pilab-dev/shadow-sso/domain"
	"github.com/pilab-dev/shadow-sso/port"
)

// EmailProvider implements port.MFAProvider for email OTP codes.
type EmailProvider struct {
	emailService   domain.EmailService
	directory      port.MFADirectory
	challengeStore port.MFAChallengeStore
}

// NewEmailProvider builds an email OTP MFA provider.
func NewEmailProvider(emailService domain.EmailService, store port.MFAChallengeStore, dir port.MFADirectory) *EmailProvider {
	return &EmailProvider{emailService: emailService, challengeStore: store, directory: dir}
}

func (p *EmailProvider) Type() domain.MfaMethodType { return domain.MfaMethodTypeEmail }
func (p *EmailProvider) Name() string               { return "Email OTP" }
func (p *EmailProvider) IsAvailable(ctx context.Context) error {
	if p.emailService == nil {
		return fmt.Errorf("email service not configured")
	}
	return nil
}

func (p *EmailProvider) newCode() string { return fmt.Sprintf("%06d", rand.Intn(1000000)) }

func (p *EmailProvider) storeChallenge(ctx context.Context, userID string, otp string) (*domain.MFAChallenge, error) {
	session, _ := json.Marshal(map[string]string{"otp": otp})
	key := uuid.NewString()
	record := &domain.MFAChallengeRecord{
		Key:         key,
		UserID:      userID,
		Provider:    domain.MfaMethodTypeEmail,
		Challenge:   otp,
		SessionData: session,
		ExpiresAt:   time.Now().Add(5 * time.Minute),
	}
	if err := p.challengeStore.Put(ctx, record); err != nil {
		return nil, err
	}
	return &domain.MFAChallenge{ID: key, Provider: domain.MfaMethodTypeEmail, ExpiresAt: record.ExpiresAt}, nil
}

func (p *EmailProvider) BeginEnrollment(ctx context.Context, user *domain.User) (*domain.MFAChallenge, error) {
	if user.Email == "" {
		return nil, fmt.Errorf("user has no email address")
	}
	otp := p.newCode()
	if err := p.emailService.SendOTPEmail(user.Email, otp); err != nil {
		return nil, err
	}
	return p.storeChallenge(ctx, user.ID, otp)
}

func (p *EmailProvider) CompleteEnrollment(ctx context.Context, user *domain.User, challengeKey string, response *domain.MFAVerification) (*domain.MfaMethod, error) {
	record, err := p.challengeStore.Consume(ctx, challengeKey)
	if err != nil {
		return nil, err
	}
	if record.UserID != user.ID {
		return nil, fmt.Errorf("challenge user mismatch")
	}
	var data map[string]string
	_ = json.Unmarshal(record.SessionData, &data)
	if string(response.Response) != data["otp"] {
		return nil, fmt.Errorf("invalid otp")
	}
	method := &domain.MfaMethod{
		ID:           uuid.NewString(),
		Type:         domain.MfaMethodTypeEmail,
		Secret:       user.Email,
		Verified:     true,
		CreatedAt:    time.Now(),
		Name:         "Email",
		CredentialID: user.Email,
	}
	if err := p.directory.AddMethod(ctx, user.ID, method); err != nil {
		return nil, err
	}
	return method, nil
}

func (p *EmailProvider) BeginChallenge(ctx context.Context, user *domain.User, method *domain.MfaMethod) (*domain.MFAChallenge, error) {
	to := user.Email
	if method != nil && method.CredentialID != "" {
		to = method.CredentialID
	}
	if to == "" {
		return nil, fmt.Errorf("no email address registered")
	}
	otp := p.newCode()
	if err := p.emailService.SendMFAEmail(to, user.FirstName, otp, "EMAIL"); err != nil {
		return nil, err
	}
	return p.storeChallenge(ctx, user.ID, otp)
}

func (p *EmailProvider) VerifyChallenge(ctx context.Context, user *domain.User, method *domain.MfaMethod, challengeKey string, response *domain.MFAVerification) (*domain.User, error) {
	record, err := p.challengeStore.Consume(ctx, challengeKey)
	if err != nil {
		return nil, err
	}
	if record.UserID != user.ID {
		return nil, fmt.Errorf("challenge user mismatch")
	}
	var data map[string]string
	_ = json.Unmarshal(record.SessionData, &data)
	if string(response.Response) != data["otp"] {
		return nil, fmt.Errorf("invalid otp")
	}
	return user, nil
}

func (p *EmailProvider) Revoke(ctx context.Context, user *domain.User, methodID string) error {
	return p.directory.DeleteMethod(ctx, user.ID, methodID)
}

var _ port.MFAProvider = (*EmailProvider)(nil)