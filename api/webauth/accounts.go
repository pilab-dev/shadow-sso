package webauth

import (
	"net/http"
	"strings"
	"time"

	"github.com/pilab-dev/shadow-sso/domain"
	"github.com/pilab-dev/shadow-sso/internal/ssosession"
)

type accountChoice struct {
	UserID   string
	Email    string
	Name     string
	Initials string
	Current  bool
}

func accountInitials(name, email string) string {
	source := strings.TrimSpace(name)
	if source == "" {
		source = strings.TrimSpace(email)
	}
	if source == "" {
		return "?"
	}
	parts := strings.Fields(source)
	firstRunes := []rune(parts[0])
	if len(firstRunes) == 0 {
		return "?"
	}
	first := firstRunes[0]
	last := first
	if len(parts) > 1 {
		lastRunes := []rune(parts[len(parts)-1])
		if len(lastRunes) > 0 {
			last = lastRunes[0]
		}
	}
	return strings.ToUpper(string(first) + string(last))
}

// loginAccounts returns the accounts stored in the signed sso_session cookie.
// Invalid, expired or tampered cookies yield an empty list.
func (wa *WebAuth) loginAccounts(r *http.Request) []ssosession.Account {
	session, err := GetSSOSession(r, wa.ssoCookieSecret)
	if err != nil || session == nil {
		return nil
	}
	return session.Accounts
}

// currentOPUserSession returns the server-side OP session referenced by the
// sso_op_session cookie, if it is still valid.
func (wa *WebAuth) currentOPUserSession(r *http.Request) (*domain.UserSession, bool) {
	cookie, err := r.Cookie(ssosession.OPSessionCookieName)
	if err != nil || cookie.Value == "" || wa.userSessionStore == nil {
		return nil, false
	}
	session, err := wa.userSessionStore.GetUserSession(r.Context(), cookie.Value)
	if err != nil || session == nil {
		return nil, false
	}
	return session, true
}

func (wa *WebAuth) accountChoices(r *http.Request) ([]accountChoice, string) {
	accounts := wa.loginAccounts(r)
	if len(accounts) == 0 {
		return nil, ""
	}

	currentUserID := ""
	if session, ok := wa.currentOPUserSession(r); ok {
		currentUserID = session.UserID
	}

	choices := make([]accountChoice, 0, len(accounts))
	for _, account := range accounts {
		choices = append(choices, accountChoice{
			UserID:   account.UserID,
			Email:    account.Email,
			Name:     account.Name,
			Initials: accountInitials(account.Name, account.Email),
			Current:  account.UserID == currentUserID,
		})
	}
	return choices, currentUserID
}

func promptRequiresLogin(prompt string) bool {
	for _, value := range strings.Fields(prompt) {
		if value == "login" {
			return true
		}
	}
	return false
}

// mergeLoginSession keeps a history of accounts in sso_session so the login
// page can show a Google-style account chooser. The most recent account is
// always first.
func (wa *WebAuth) mergeLoginSession(r *http.Request, account ssosession.Account) *ssosession.Session {
	existing, err := GetSSOSession(r, wa.ssoCookieSecret)
	if err != nil {
		existing = nil
	}
	if account.LastUsed.IsZero() {
		account.LastUsed = time.Now()
	}
	return ssosession.MergeAccount(existing, account)
}
