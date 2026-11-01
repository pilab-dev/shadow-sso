package ssosession

// FederationStateCookieName is the cookie that carries the CSRF state nonce for
// social/federated logins. It is shared by the webauth login handlers and the
// federated callback so both sides cannot drift apart.
const FederationStateCookieName = "sso_federation_state"
