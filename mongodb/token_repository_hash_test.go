package mongodb

import (
	"testing"

	"github.com/pilab-dev/shadow-sso/domain"
)

func TestPrepareTokenForStorage_HashesRefreshToken(t *testing.T) {
	tok := &domain.Token{TokenType: "refresh_token", TokenValue: "raw-refresh-jwt"}
	stored := prepareTokenForStorage(tok)
	if stored.TokenValue != "" {
		t.Fatalf("raw refresh token persisted: %q", stored.TokenValue)
	}
	if stored.TokenHash != hashTokenValue("raw-refresh-jwt") {
		t.Fatalf("unexpected hash: %q", stored.TokenHash)
	}
	// The caller must keep the raw value so it can return it to the client.
	if tok.TokenValue != "raw-refresh-jwt" {
		t.Fatalf("caller token value was mutated: %q", tok.TokenValue)
	}
}

func TestPrepareTokenForStorage_LeavesAccessToken(t *testing.T) {
	tok := &domain.Token{TokenType: "access_token", TokenValue: "raw-access-jwt"}
	stored := prepareTokenForStorage(tok)
	if stored.TokenValue != "raw-access-jwt" {
		t.Fatalf("access token value changed: %q", stored.TokenValue)
	}
	if tok.TokenValue != "raw-access-jwt" {
		t.Fatalf("caller access token value changed: %q", tok.TokenValue)
	}
}

// TestStoreToken_KeepsCallerValue guards the regression where hashing at rest
// mutated the caller's token, causing GenerateTokenPairWithSession to return an
// empty refresh_token.
func TestStoreToken_PersistsHashButKeepsCallerValue(t *testing.T) {
	tok := &domain.Token{ID: "rt-1", TokenType: "refresh_token", TokenValue: "raw-refresh-jwt"}
	stored := prepareTokenForStorage(tok)
	if stored.ID != tok.ID {
		t.Fatalf("copy lost fields: got id %q", stored.ID)
	}
	if tok.TokenValue != "raw-refresh-jwt" || tok.TokenHash != "" {
		t.Fatalf("caller token mutated: %+v", tok)
	}
}
