package mfa

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/pilab-dev/shadow-sso/domain"
	"github.com/pilab-dev/shadow-sso/port"
)

// PushProvider implements port.MFAProvider for Firebase/APNs push MFA.
type PushProvider struct {
	pushMFA        port.PushMFAProvider
	directory      port.MFADirectory
	challengeStore port.MFAChallengeStore
}

func NewPushProvider(pushMFA port.PushMFAProvider, store port.MFAChallengeStore, dir port.MFADirectory) *PushProvider {
	return &PushProvider{pushMFA: pushMFA, challengeStore: store, directory: dir}
}

func (p *PushProvider) Type() domain.MfaMethodType { return domain.MfaMethodTypePush }
func (p *PushProvider) Name() string                 { return "Push (Firebase)" }
func (p *PushProvider) IsAvailable(ctx context.Context) error {
	if p.pushMFA == nil {
		return fmt.Errorf("push mfa service not configured")
	}
	return nil
}

func (p *PushProvider) BeginEnrollment(ctx context.Context, user *domain.User) (*domain.MFAChallenge, error) {
	// Enrollment assumes device tokens already registered via PushMFAService.
	method := &domain.MfaMethod{
		ID:        uuid.NewString(),
		Type:      domain.MfaMethodTypePush,
		Verified:  true,
		CreatedAt: time.Now(),
		Name:      "Push",
	}
	if err := p.directory.AddMethod(ctx, user.ID, method); err != nil {
		return nil, err
	}
	if err := p.pushMFA.EnablePushMFA(ctx, user.ID); err != nil {
		return nil, err
	}
	return &domain.MFAChallenge{ID: method.ID, Provider: domain.MfaMethodTypePush}, nil
}

func (p *PushProvider) CompleteEnrollment(ctx context.Context, user *domain.User, challengeKey string, response *domain.MFAVerification) (*domain.MfaMethod, error) {
	// Push enrollment is completed during BeginEnrollment; nothing to verify.
	method, err := p.directory.GetMethod(ctx, user.ID, challengeKey)
	if err != nil {
		return nil, err
	}
	return method, nil
}

func (p *PushProvider) BeginChallenge(ctx context.Context, user *domain.User, method *domain.MfaMethod) (*domain.MFAChallenge, error) {
	challengeID, err := p.pushMFA.CreatePushMFAChallenge(ctx, user, "", "")
	if err != nil {
		return nil, err
	}
	session, _ := json.Marshal(map[string]string{"challenge_id": challengeID})
	key := uuid.NewString()
	record := &domain.MFAChallengeRecord{
		Key:         key,
		UserID:      user.ID,
		Provider:    domain.MfaMethodTypePush,
		Challenge:   challengeID,
		SessionData: session,
		ExpiresAt:   time.Now().Add(5 * time.Minute),
	}
	if err := p.challengeStore.Put(ctx, record); err != nil {
		return nil, err
	}
	return &domain.MFAChallenge{ID: key, Provider: domain.MfaMethodTypePush, Challenge: challengeID, ExpiresAt: record.ExpiresAt}, nil
}

func (p *PushProvider) VerifyChallenge(ctx context.Context, user *domain.User, method *domain.MfaMethod, challengeKey string, response *domain.MFAVerification) (*domain.User, error) {
	record, err := p.challengeStore.Consume(ctx, challengeKey)
	if err != nil {
		return nil, err
	}
	if record.UserID != user.ID {
		return nil, fmt.Errorf("challenge user mismatch")
	}
	var data map[string]string
	_ = json.Unmarshal(record.SessionData, &data)
	status, err := p.pushMFA.GetPushMFAChallengeStatus(ctx, user.ID, data["challenge_id"])
	if err != nil {
		return nil, err
	}
	if status != "APPROVED" {
		return nil, fmt.Errorf("push challenge not approved (status=%s)", status)
	}
	return user, nil
}

func (p *PushProvider) Revoke(ctx context.Context, user *domain.User, methodID string) error {
	if err := p.pushMFA.DisablePushMFA(ctx, user.ID); err != nil {
		return err
	}
	return p.directory.DeleteMethod(ctx, user.ID, methodID)
}
