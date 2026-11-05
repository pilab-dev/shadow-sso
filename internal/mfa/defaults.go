package mfa

import (
	"github.com/pilab-dev/shadow-sso/domain"
	"github.com/pilab-dev/shadow-sso/port"
)

// BuildDefaultRegistry wires the built-in MFA providers into a registry.
func BuildDefaultRegistry(
	store port.MFAChallengeStore,
	dir port.MFADirectory,
	webauthnCfg WebAuthnConfig,
	yubicoCfg YubicoConfig,
	smsService domain.SMSService,
	emailService domain.EmailService,
	pushMFA port.PushMFAProvider,
) (*DefaultMFARegistry, error) {
	reg := NewMFARegistry()
	wa, err := NewWebAuthnProvider(webauthnCfg, store, dir)
	if err != nil {
		return nil, err
	}
	if err := reg.Register(wa); err != nil {
		return nil, err
	}
	reg.Register(NewYubicoProvider(yubicoCfg, store, dir))
	reg.Register(NewSMSProvider(smsService, store, dir))
	if emailService != nil {
		reg.Register(NewEmailProvider(emailService, store, dir))
	}
	reg.Register(NewPushProvider(pushMFA, store, dir))
	return reg, nil
}
