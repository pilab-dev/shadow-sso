package mfa

import (
	"context"
	"fmt"
	"testing"

	"github.com/pilab-dev/shadow-sso/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeEmailService struct {
	lastOTP string
	sent    int
}

func (f *fakeEmailService) SendVerificationEmail(to, name, link string) error { return nil }
func (f *fakeEmailService) SendPasswordResetEmail(to, name, link string) error { return nil }
func (f *fakeEmailService) SendOTPEmail(to, otp string) error {
	f.lastOTP = otp
	f.sent++
	return nil
}
func (f *fakeEmailService) SendMFAEmail(to, name, otp, method string) error {
	f.lastOTP = otp
	f.sent++
	return nil
}

type fakeMFADirectory struct {
	methods []domain.MfaMethod
}

func (f *fakeMFADirectory) GetUser(ctx context.Context, userID string) (*domain.User, error) {
	return &domain.User{ID: userID}, nil
}
func (f *fakeMFADirectory) AddMethod(ctx context.Context, userID string, method *domain.MfaMethod) error {
	f.methods = append(f.methods, *method)
	return nil
}
func (f *fakeMFADirectory) GetMethod(ctx context.Context, userID, methodID string) (*domain.MfaMethod, error) {
	return nil, fmt.Errorf("not found")
}
func (f *fakeMFADirectory) ListMethods(ctx context.Context, userID string) ([]domain.MfaMethod, error) {
	return f.methods, nil
}
func (f *fakeMFADirectory) UpdateMethod(ctx context.Context, userID string, method *domain.MfaMethod) error {
	return nil
}
func (f *fakeMFADirectory) DeleteMethod(ctx context.Context, userID, methodID string) error { return nil }
func (f *fakeMFADirectory) FindByCredentialID(ctx context.Context, credentialID string) (*domain.User, *domain.MfaMethod, error) {
	return nil, nil, fmt.Errorf("not found")
}

func TestEmailProvider_EnrollmentAndChallenge(t *testing.T) {
	ctx := context.Background()
	mail := &fakeEmailService{}
	dir := &fakeMFADirectory{}
	store := NewInMemoryChallengeStore()
	provider := NewEmailProvider(mail, store, dir)

	user := &domain.User{ID: "u1", Email: "user@example.com", FirstName: "Test"}
	enroll, err := provider.BeginEnrollment(ctx, user)
	require.NoError(t, err)
	require.NotEmpty(t, enroll.ID)
	require.Equal(t, 1, mail.sent)

	method, err := provider.CompleteEnrollment(ctx, user, enroll.ID, &domain.MFAVerification{Response: []byte(mail.lastOTP)})
	require.NoError(t, err)
	assert.Equal(t, domain.MfaMethodTypeEmail, method.Type)
	assert.Len(t, dir.methods, 1)

	challenge, err := provider.BeginChallenge(ctx, user, method)
	require.NoError(t, err)
	require.NotEmpty(t, challenge.ID)
	require.Equal(t, 2, mail.sent)

	verified, err := provider.VerifyChallenge(ctx, user, method, challenge.ID, &domain.MFAVerification{Response: []byte(mail.lastOTP)})
	require.NoError(t, err)
	assert.Equal(t, user.ID, verified.ID)
}

func TestEmailProvider_NoEmail(t *testing.T) {
	provider := NewEmailProvider(&fakeEmailService{}, NewInMemoryChallengeStore(), &fakeMFADirectory{})
	_, err := provider.BeginEnrollment(context.Background(), &domain.User{ID: "u2"})
	require.Error(t, err)
}

func TestDefaultRegistryIncludesEmail(t *testing.T) {
	reg, err := BuildDefaultRegistry(
		NewInMemoryChallengeStore(),
		&fakeMFADirectory{},
		WebAuthnConfig{RPID: "localhost", RPName: "Test", RPOrigins: []string{"http://localhost"}},
		YubicoConfig{},
		nil,
		&fakeEmailService{},
		nil,
	)
	require.NoError(t, err)
	_, ok := reg.Get(domain.MfaMethodTypeEmail)
	assert.True(t, ok, "email provider must be registered")
}