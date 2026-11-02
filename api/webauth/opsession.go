package webauth

import (
	"github.com/gin-gonic/gin"
	"github.com/pilab-dev/shadow-sso/domain"
	"github.com/pilab-dev/shadow-sso/internal/ssosession"
)

// establishOPSession creates the server-side OP session consumed by
// /oauth2/authorize and sets the sso_op_session cookie. This is what makes a
// successful web login reusable as SSO for other OIDC clients.
func (wa *WebAuth) establishOPSession(c *gin.Context, userID string) (*domain.UserSession, error) {
	return ssosession.EstablishOPSession(
		c.Request.Context(),
		wa.userSessionStore,
		c.Writer,
		c.Request,
		userID,
		IsSecureRequest(c.Request),
	)
}
