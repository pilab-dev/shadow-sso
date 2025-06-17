package mongodb

const (
	UsersCollection        = "oauth_users"
	ClientsCollection      = "oauth_clients"
	CodesCollection        = "oauth_auth_codes"
	TokensCollection       = "oauth_tokens"      // For user OAuth tokens
	ChallengesCollection   = "oauth_pkce_challenges"
	UserSessionsCollection = "oauth_user_sessions" // For user login sessions (if stored in mongo)

	// New collections
	ServiceAccountsCollection = "service_accounts"
	PublicKeysCollection      = "public_keys" // For service account public keys
)
