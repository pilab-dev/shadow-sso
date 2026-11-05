package mfa

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/pilab-dev/shadow-sso/domain"
	"github.com/pilab-dev/shadow-sso/port"
)

// WebAuthnConfig configures the WebAuthn provider.
type WebAuthnConfig struct {
	RPID       string
	RPName     string
	RPOrigins  []string
	UserVerification protocol.UserVerificationRequirement
}

// WebAuthnProvider implements port.MFAProvider for passkeys, platform
// authenticators (macOS Touch ID) and security keys (YubiKey).
type WebAuthnProvider struct {
	wa            *webauthn.WebAuthn
	cfg           WebAuthnConfig
	challengeStore port.MFAChallengeStore
	directory     port.MFADirectory
}

func NewWebAuthnProvider(cfg WebAuthnConfig, store port.MFAChallengeStore, dir port.MFADirectory) (*WebAuthnProvider, error) {
	wa, err := webauthn.New(&webauthn.Config{
		RPDisplayName: cfg.RPName,
		RPID:          cfg.RPID,
		RPOrigins:     cfg.RPOrigins,
	})
	if err != nil {
		return nil, err
	}
	if cfg.UserVerification == "" {
		cfg.UserVerification = protocol.VerificationRequired
	}
	return &WebAuthnProvider{wa: wa, cfg: cfg, challengeStore: store, directory: dir}, nil
}

func (p *WebAuthnProvider) Type() domain.MfaMethodType { return domain.MfaMethodTypeWebAuthn }
func (p *WebAuthnProvider) Name() string                 { return "WebAuthn / Passkey" }
func (p *WebAuthnProvider) IsAvailable(ctx context.Context) error { return nil }

type webAuthnUser struct {
	user  *domain.User
	creds []webauthn.Credential
}

func (u webAuthnUser) WebAuthnID() []byte          { return []byte(u.user.ID) }
func (u webAuthnUser) WebAuthnName() string        { return u.user.Email }
func (u webAuthnUser) WebAuthnDisplayName() string { return u.user.FirstName + " " + u.user.LastName }
func (u webAuthnUser) WebAuthnCredentials() []webauthn.Credential {
	return u.creds
}

func (p *WebAuthnProvider) loadCredentials(user *domain.User) []webauthn.Credential {
	var creds []webauthn.Credential
	methods, _ := p.directory.ListMethods(context.Background(), user.ID)
	for _, m := range methods {
		if m.Type != domain.MfaMethodTypeWebAuthn || m.Secret == "" {
			continue
		}
		var c webauthn.Credential
		if err := json.Unmarshal([]byte(m.Secret), &c); err == nil {
			creds = append(creds, c)
		}
	}
	return creds
}

func (p *WebAuthnProvider) BeginEnrollment(ctx context.Context, user *domain.User) (*domain.MFAChallenge, error) {
	ua := webAuthnUser{user: user}
	creation, session, err := p.wa.BeginRegistration(
		ua,
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementRequired,
			UserVerification: p.cfg.UserVerification,
		}),
	)
	if err != nil {
		return nil, err
	}
	sessionBytes, _ := json.Marshal(session)
	key := uuid.NewString()
	record := &domain.MFAChallengeRecord{
		Key:         key,
		UserID:      user.ID,
		Provider:    domain.MfaMethodTypeWebAuthn,
		Challenge:   session.Challenge,
		SessionData: sessionBytes,
		ExpiresAt:   session.Expires,
	}
	if err := p.challengeStore.Put(ctx, record); err != nil {
		return nil, err
	}
	opts, _ := json.Marshal(creation)
	return &domain.MFAChallenge{
		ID:        key,
		Provider:  domain.MfaMethodTypeWebAuthn,
		Challenge: session.Challenge,
		Options:   opts,
		ExpiresAt: session.Expires,
	}, nil
}

func (p *WebAuthnProvider) CompleteEnrollment(ctx context.Context, user *domain.User, challengeKey string, response *domain.MFAVerification) (*domain.MfaMethod, error) {
	record, err := p.challengeStore.Consume(ctx, challengeKey)
	if err != nil {
		return nil, err
	}
	if record.UserID != user.ID {
		return nil, errors.New("challenge user mismatch")
	}
	var session webauthn.SessionData
	if err := json.Unmarshal(record.SessionData, &session); err != nil {
		return nil, err
	}
	ua := webAuthnUser{user: user, creds: p.loadCredentials(user)}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(response.Response)
	if err != nil {
		return nil, err
	}
	cred, err := p.wa.CreateCredential(ua, session, parsed)
	if err != nil {
		return nil, err
	}
	credBytes, _ := json.Marshal(cred)
	method := &domain.MfaMethod{
		ID:           uuid.NewString(),
		Type:         domain.MfaMethodTypeWebAuthn,
		Secret:       string(credBytes),
		Verified:     true,
		CreatedAt:    time.Now(),
		Name:         "Passkey / Security Key",
		CredentialID: string(cred.ID),
		Counter:      int32(cred.Authenticator.SignCount),
	}
	if err := p.directory.AddMethod(ctx, user.ID, method); err != nil {
		return nil, err
	}
	return method, nil
}

func (p *WebAuthnProvider) BeginChallenge(ctx context.Context, user *domain.User, method *domain.MfaMethod) (*domain.MFAChallenge, error) {
	ua := webAuthnUser{user: user, creds: p.loadCredentials(user)}
	var assertion *protocol.CredentialAssertion
	var session *webauthn.SessionData
	var err error
	if method == nil {
		// Discoverable / passkey flow.
		a, s, e := p.wa.BeginDiscoverableLogin()
		assertion, session, err = a, s, e
	} else {
		a, s, e := p.wa.BeginLogin(ua)
		assertion, session, err = a, s, e
	}
	if err != nil {
		return nil, err
	}
	sessionBytes, _ := json.Marshal(session)
	key := uuid.NewString()
	record := &domain.MFAChallengeRecord{
		Key:         key,
		UserID:      user.ID,
		Provider:    domain.MfaMethodTypeWebAuthn,
		Challenge:   session.Challenge,
		SessionData: sessionBytes,
		ExpiresAt:   session.Expires,
	}
	if method == nil {
		record.UserID = ""
	}
	if err := p.challengeStore.Put(ctx, record); err != nil {
		return nil, err
	}
	opts, _ := json.Marshal(assertion)
	return &domain.MFAChallenge{
		ID:        key,
		Provider:  domain.MfaMethodTypeWebAuthn,
		Challenge: session.Challenge,
		Options:   opts,
		ExpiresAt: session.Expires,
	}, nil
}

func (p *WebAuthnProvider) VerifyChallenge(ctx context.Context, user *domain.User, method *domain.MfaMethod, challengeKey string, response *domain.MFAVerification) (*domain.User, error) {
	record, err := p.challengeStore.Consume(ctx, challengeKey)
	if err != nil {
		return nil, err
	}
	var session webauthn.SessionData
	if err := json.Unmarshal(record.SessionData, &session); err != nil {
		return nil, err
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(response.Response)
	if err != nil {
		return nil, err
	}

	if record.UserID == "" {
		// Discoverable / passkey login.
		handler := func(rawID, userHandle []byte) (webauthn.User, error) {
			u, _, err := p.directory.FindByCredentialID(ctx, string(rawID))
			if err != nil {
				return nil, err
			}
			if u == nil {
				return nil, errors.New("unknown credential")
			}
			return webAuthnUser{user: u, creds: p.loadCredentials(u)}, nil
		}
		u, cred, err := p.wa.ValidatePasskeyLogin(handler, session, parsed)
		if err != nil {
			return nil, err
		}
		// Update counter via directory if possible.
		du, _ := u.(webAuthnUser)
		if du.user != nil {
			p.updateCounter(ctx, du.user, cred)
		}
		return du.user, nil
	}

	if user == nil {
		u, err := p.directory.GetUser(ctx, record.UserID)
		if err != nil {
			return nil, err
		}
		user = u
	}
	ua := webAuthnUser{user: user, creds: p.loadCredentials(user)}
	cred, err := p.wa.ValidateLogin(ua, session, parsed)
	if err != nil {
		return nil, err
	}
	p.updateCounter(ctx, user, cred)
	return user, nil
}

func (p *WebAuthnProvider) updateCounter(ctx context.Context, user *domain.User, cred *webauthn.Credential) {
	methods, _ := p.directory.ListMethods(ctx, user.ID)
	for i := range methods {
		if methods[i].CredentialID == string(cred.ID) || methods[i].Secret != "" {
			// Best-effort: update the matching method's counter.
			if methods[i].CredentialID == string(cred.ID) {
				methods[i].Counter = int32(cred.Authenticator.SignCount)
				_ = p.directory.UpdateMethod(ctx, user.ID, &methods[i])
			}
		}
	}
}

func (p *WebAuthnProvider) Revoke(ctx context.Context, user *domain.User, methodID string) error {
	return p.directory.DeleteMethod(ctx, user.ID, methodID)
}
