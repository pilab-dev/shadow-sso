package mfa

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/pilab-dev/shadow-sso/domain"
	"github.com/pilab-dev/shadow-sso/port"
)

// YubicoConfig configures the Yubico OTP provider.
type YubicoConfig struct {
	ClientID int
	APIKey   string // base64-encoded secret for HMAC (optional but recommended)
	APIURL   string
}

// YubicoProvider implements port.MFAProvider for YubiKey OTP.
type YubicoProvider struct {
	cfg           YubicoConfig
	httpClient    *http.Client
	challengeStore port.MFAChallengeStore
	directory     port.MFADirectory
}

func NewYubicoProvider(cfg YubicoConfig, store port.MFAChallengeStore, dir port.MFADirectory) *YubicoProvider {
	if cfg.APIURL == "" {
		cfg.APIURL = "https://api.yubico.com/wsapi/2.0/verify"
	}
	return &YubicoProvider{cfg: cfg, httpClient: &http.Client{Timeout: 10 * time.Second}, challengeStore: store, directory: dir}
}

func (p *YubicoProvider) Type() domain.MfaMethodType { return domain.MfaMethodTypeYubico }
func (p *YubicoProvider) Name() string                 { return "YubiKey OTP" }
func (p *YubicoProvider) IsAvailable(ctx context.Context) error {
	if p.cfg.ClientID == 0 {
		return fmt.Errorf("yubico client id not configured")
	}
	return nil
}

func (p *YubicoProvider) BeginEnrollment(ctx context.Context, user *domain.User) (*domain.MFAChallenge, error) {
	key := uuid.NewString()
	record := &domain.MFAChallengeRecord{
		Key:       key,
		UserID:    user.ID,
		Provider:  domain.MfaMethodTypeYubico,
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}
	if err := p.challengeStore.Put(ctx, record); err != nil {
		return nil, err
	}
	return &domain.MFAChallenge{
		ID:        key,
		Provider:  domain.MfaMethodTypeYubico,
		ExpiresAt: record.ExpiresAt,
	}, nil
}

func (p *YubicoProvider) CompleteEnrollment(ctx context.Context, user *domain.User, challengeKey string, response *domain.MFAVerification) (*domain.MfaMethod, error) {
	record, err := p.challengeStore.Consume(ctx, challengeKey)
	if err != nil {
		return nil, err
	}
	if record.UserID != user.ID {
		return nil, fmt.Errorf("challenge user mismatch")
	}
	otp := strings.TrimSpace(string(response.Response))
	if len(otp) != 44 {
		return nil, fmt.Errorf("invalid yubikey otp length")
	}
	if err := p.verifyOTP(ctx, otp); err != nil {
		return nil, err
	}
	method := &domain.MfaMethod{
		ID:           uuid.NewString(),
		Type:         domain.MfaMethodTypeYubico,
		Secret:       otp[:12], // store the public ID prefix
		Verified:     true,
		CreatedAt:    time.Now(),
		Name:         "YubiKey",
		CredentialID: otp[:12],
	}
	if err := p.directory.AddMethod(ctx, user.ID, method); err != nil {
		return nil, err
	}
	return method, nil
}

func (p *YubicoProvider) BeginChallenge(ctx context.Context, user *domain.User, method *domain.MfaMethod) (*domain.MFAChallenge, error) {
	key := uuid.NewString()
	record := &domain.MFAChallengeRecord{
		Key:       key,
		UserID:    user.ID,
		Provider:  domain.MfaMethodTypeYubico,
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}
	if err := p.challengeStore.Put(ctx, record); err != nil {
		return nil, err
	}
	return &domain.MFAChallenge{
		ID:        key,
		Provider:  domain.MfaMethodTypeYubico,
		ExpiresAt: record.ExpiresAt,
	}, nil
}

func (p *YubicoProvider) VerifyChallenge(ctx context.Context, user *domain.User, method *domain.MfaMethod, challengeKey string, response *domain.MFAVerification) (*domain.User, error) {
	record, err := p.challengeStore.Consume(ctx, challengeKey)
	if err != nil {
		return nil, err
	}
	if record.UserID != user.ID {
		return nil, fmt.Errorf("challenge user mismatch")
	}
	otp := strings.TrimSpace(string(response.Response))
	if len(otp) != 44 || method == nil || otp[:12] != method.CredentialID {
		return nil, fmt.Errorf("invalid yubikey otp")
	}
	if err := p.verifyOTP(ctx, otp); err != nil {
		return nil, err
	}
	return user, nil
}

func (p *YubicoProvider) Revoke(ctx context.Context, user *domain.User, methodID string) error {
	return p.directory.DeleteMethod(ctx, user.ID, methodID)
}

func (p *YubicoProvider) verifyOTP(ctx context.Context, otp string) error {
	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		return err
	}
	nonce := hex.EncodeToString(nonceBytes)
	params := url.Values{}
	params.Set("id", fmt.Sprintf("%d", p.cfg.ClientID))
	params.Set("otp", otp)
	params.Set("nonce", nonce)
	resp, err := p.httpClient.Get(p.cfg.APIURL + "?" + params.Encode())
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	text := string(body)
	if !strings.Contains(text, "status=OK") {
		return fmt.Errorf("yubico verification failed: %s", strings.TrimSpace(text))
	}
	return nil
}
