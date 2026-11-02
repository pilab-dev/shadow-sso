package webauth

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// SessionHandler returns the identity carried by the sso_session cookie. It is
// a read-only endpoint for first-party applications on trusted origins; it does
// not issue tokens and must not be used as an alternative to the OIDC flow for
// third-party clients.
func (wa *WebAuth) SessionHandler(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	c.Header("Pragma", "no-cache")
	c.Header("Vary", "Cookie")

	session, err := GetSSOSession(c.Request, wa.ssoCookieSecret)
	if err != nil || session == nil || len(session.Accounts) == 0 {
		c.JSON(http.StatusOK, gin.H{"authenticated": false})
		return
	}

	// A session may contain multiple accounts; return the most recently used.
	account := session.Accounts[0]
	for _, candidate := range session.Accounts[1:] {
		if candidate.LastUsed.After(account.LastUsed) {
			account = candidate
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"authenticated": true,
		"user": gin.H{
			"id":      account.UserID,
			"email":   account.Email,
			"name":    account.Name,
			"picture": account.Picture,
		},
	})
}
