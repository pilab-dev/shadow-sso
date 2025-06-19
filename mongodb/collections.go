package mongodb

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
