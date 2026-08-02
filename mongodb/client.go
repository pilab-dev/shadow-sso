package mongodb

import (
	"net/url"
)

const (
	UsersCollection           = "oauth_users"           // For users
	ClientsCollection         = "oauth_clients"         // For OAuth clients
	CodesCollection           = "oauth_auth_codes"      // For authorization codes
	TokensCollection          = "oauth_tokens"          // For user OAuth tokens
	ChallengesCollection      = "oauth_pkce_challenges" // For PKCE challenges
	UserSessionsCollection    = "oauth_user_sessions"   // For user login sessions (if stored in mongo)
	ServiceAccountsCollection = "service_accounts"      // For service accounts
	PublicKeysCollection      = "public_keys"           // For service account public keys
	IdPsCollection            = "identity_providers"    // For identity providers
	DeviceAuthCollectionName  = "device_authorizations" // For device authorization codes (RFC 8628)
)

// maskMongoURI strips user:password credentials from a MongoDB URI for safe logging.
func maskMongoURI(rawURI string) string {
	parsed, err := url.Parse(rawURI)
	if err != nil {
		return "<invalid-uri>"
	}
	if parsed.User != nil {
		parsed.User = url.User("****")
	}
	return parsed.String()
}
