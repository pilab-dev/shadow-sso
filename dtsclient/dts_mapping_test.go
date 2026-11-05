package dtsclient

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/pilab-dev/shadow-sso/domain"
)

func TestAuthCodeMappingKeepsNonce(t *testing.T) {
	in := &domain.AuthCode{Code: "c", Nonce: "n-1", ExpiresAt: time.Now().Add(time.Minute)}
	out := fromProtoAuthCode(toProtoAuthCode(in))
	assert.Equal(t, "n-1", out.Nonce)
}

func TestRefreshTokenMappingKeepsSessionAndFamily(t *testing.T) {
	in := &domain.Token{
		TokenType: domain.TokenTypeRefreshToken, TokenValue: "r", ExpiresAt: time.Now().Add(time.Hour),
		SessionID: "s-1", Family: "f-1", ParentJTI: "p-1",
	}
	out := protoRefreshTokenToDomainToken(domainTokenToProtoRefreshToken(in))
	assert.Equal(t, "s-1", out.SessionID)
	assert.Equal(t, "f-1", out.Family)
	assert.Equal(t, "p-1", out.ParentJTI)
}
