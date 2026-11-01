package ssosession

import (
	"context"
	"net/http"
	"time"

	"github.com/pilab-dev/shadow-sso/domain"
)

const (
	// OPSessionCookieName is the cookie that points at a server-side
	// domain.UserSession. It is the session consulted by /oauth2/authorize;
	// the sso_session cookie is the login UI's own identity cookie.
	OPSessionCookieName = "sso_op_session"

	// OPSessionTTL is how long a web login remains valid for cross-application
	// SSO. Keep it in sync with the OIDC provider's session expectations.
	OPSessionTTL = 24 * time.Hour
)

// EstablishOPSession creates a server-side OP user session for userID and sets
// the sso_op_session cookie. A nil store means OP sessions are not configured;
// in that case it is a no-op so callers can degrade gracefully.
func EstablishOPSession(
	ctx context.Context,
	store domain.UserSessionStore,
	w http.ResponseWriter,
	r *http.Request,
	userID string,
	isSecure bool,
) (*domain.UserSession, error) {
	if store == nil || userID == "" {
		return nil, nil
	}

	now := time.Now()
	session := &domain.UserSession{
		SessionID:       NewID(),
		UserID:          userID,
		AuthenticatedAt: now,
		ExpiresAt:       now.Add(OPSessionTTL),
	}
	if r != nil {
		session.UserAgent = r.UserAgent()
	}

	if err := store.StoreUserSession(ctx, session); err != nil {
		return nil, err
	}
	SetOPSessionCookie(w, session.SessionID, isSecure)
	return session, nil
}

// SetOPSessionCookie sets the opaque server-side OP session cookie. In secure
// deployments it uses SameSite=None so the cookie is also sent when the
// authorize endpoint is loaded in a cross-site iframe for silent login.
func SetOPSessionCookie(w http.ResponseWriter, sessionID string, isSecure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     OPSessionCookieName,
		Value:    sessionID,
		Path:     "/",
		MaxAge:   int(OPSessionTTL.Seconds()),
		Expires:  time.Now().Add(OPSessionTTL),
		HttpOnly: true,
		Secure:   isSecure,
		SameSite: opSessionSameSite(isSecure),
	})
}

// ClearOPSessionCookie immediately expires the OP session cookie.
func ClearOPSessionCookie(w http.ResponseWriter, isSecure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     OPSessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		Secure:   isSecure,
		SameSite: opSessionSameSite(isSecure),
	})
}

func opSessionSameSite(isSecure bool) http.SameSite {
	if isSecure {
		return http.SameSiteNoneMode
	}
	return http.SameSiteLaxMode
}
