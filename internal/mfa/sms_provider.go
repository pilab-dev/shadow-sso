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

// SMSProvider implements port.MFAProvider for SMS OTP.
type SMSProvider struct {
	smsService     domain.SMSService
	directory      port.MFADirectory
	challengeStore port.MFAChallengeStore
}

func NewSMSProvider(smsService domain.SMSService, store port.MFAChallengeStore, dir port.MFADirectory) *SMSProvider {
	return &SMSProvider{smsService: smsService, challengeStore: store, directory: dir}
}

func (p *SMSProvider) Type() domain.MfaMethodType { return domain.MfaMethodTypeSMS }
func (p *SMSProvider) Name() string                 { return "SMS OTP" }
func (p *SMSProvider) IsAvailable(ctx context.Context) error {
	if p.smsService == nil {
		return fmt.Errorf("sms service not configured")
	}
	return nil
}

func generateOTP() string {
	return fmt.Sprintf("%06d", rand.Intn(1000000))
}

func (p *SMSProvider) BeginEnrollment(ctx context.Context, user *domain.User) (*domain.MFAChallenge, error) {
	if user.PhoneNumber == "" {
		return nil, fmt.Errorf("user has no phone number")
	}
	otp := generateOTP()
	if err := p.smsService.SendOTP(user.PhoneNumber, otp); err != nil {
		return nil, err
	}
	session, _ := json.Marshal(map[string]string{"otp": otp})
	key := uuid.NewString()
	record := &domain.MFAChallengeRecord{
		Key:         key,
		UserID:      user.ID,
		Provider:    domain.MfaMethodTypeSMS,
		Challenge:   otp,
		SessionData: session,
		ExpiresAt:   time.Now().Add(5 * time.Minute),
	}
	if err := p.challengeStore.Put(ctx, record); err != nil {
		return nil, err
	}
	return &domain.MFAChallenge{ID: key, Provider: domain.MfaMethodTypeSMS, ExpiresAt: record.ExpiresAt}, nil
}

func (p *SMSProvider) CompleteEnrollment(ctx context.Context, user *domain.User, challengeKey string, response *domain.MFAVerification) (*domain.MfaMethod, error) {
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
		Type:         domain.MfaMethodTypeSMS,
		Secret:       user.PhoneNumber,
		Verified:     true,
		CreatedAt:    time.Now(),
		Name:         "SMS",
		CredentialID: user.PhoneNumber,
	}
	if err := p.directory.AddMethod(ctx, user.ID, method); err != nil {
		return nil, err
	}
	return method, nil
}

func (p *SMSProvider) BeginChallenge(ctx context.Context, user *domain.User, method *domain.MfaMethod) (*domain.MFAChallenge, error) {
	if method == nil || method.CredentialID == "" {
		return nil, fmt.Errorf("no phone number registered")
	}
	otp := generateOTP()
	if err := p.smsService.SendOTP(method.CredentialID, otp); err != nil {
		return nil, err
	}
	session, _ := json.Marshal(map[string]string{"otp": otp})
	key := uuid.NewString()
	record := &domain.MFAChallengeRecord{
		Key:         key,
		UserID:      user.ID,
		Provider:    domain.MfaMethodTypeSMS,
		Challenge:   otp,
		SessionData: session,
		ExpiresAt:   time.Now().Add(5 * time.Minute),
	}
	if err := p.challengeStore.Put(ctx, record); err != nil {
		return nil, err
	}
	return &domain.MFAChallenge{ID: key, Provider: domain.MfaMethodTypeSMS, ExpiresAt: record.ExpiresAt}, nil
}

func (p *SMSProvider) VerifyChallenge(ctx context.Context, user *domain.User, method *domain.MfaMethod, challengeKey string, response *domain.MFAVerification) (*domain.User, error) {
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

func (p *SMSProvider) Revoke(ctx context.Context, user *domain.User, methodID string) error {
	return p.directory.DeleteMethod(ctx, user.ID, methodID)
}
