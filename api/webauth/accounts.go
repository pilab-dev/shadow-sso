package webauth

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/pilab-dev/shadow-sso/domain"
	"github.com/pilab-dev/shadow-sso/internal/ssosession"
)

type accountChoice struct {
	UserID       string
	Email        string
	Name         string
	Initials     string
	Current      bool
	SignedIn     bool
	StatusText   string
	StatusTone   string
	LastUsedText string
}

func relativeTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	delta := time.Since(t)
	switch {
	case delta < time.Minute:
		return "just now"
	case delta < time.Hour:
		minutes := int(delta.Minutes())
		if minutes == 1 {
			return "1 minute ago"
		}
		return fmt.Sprintf("%d minutes ago", minutes)
	case delta < 24*time.Hour:
		hours := int(delta.Hours())
		if hours == 1 {
			return "1 hour ago"
		}
		return fmt.Sprintf("%d hours ago", hours)
	default:
		days := int(delta.Hours() / 24)
		if days == 1 {
			return "1 day ago"
		}
		return fmt.Sprintf("%d days ago", days)
	}
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
		current := account.UserID == currentUserID
		signedIn := current
		if !signedIn && account.OPSessionID != "" && wa.userSessionStore != nil {
			if session, err := wa.userSessionStore.GetUserSession(r.Context(), account.OPSessionID); err == nil &&
				session != nil && session.UserID == account.UserID {
				signedIn = true
			}
		}

		statusText := "Signed out"
		statusTone := "signed-out"
		if current {
			statusText = "Current session"
			statusTone = "current"
		} else if signedIn {
			statusText = "Signed in"
			statusTone = "signed-in"
		}

		lastUsedText := ""
		if !current {
			if relative := relativeTime(account.LastUsed); relative != "" {
				lastUsedText = "Last used " + relative
			} else {
				lastUsedText = "Last used"
			}
		}

		choices = append(choices, accountChoice{
			UserID:       account.UserID,
			Email:        account.Email,
			Name:         account.Name,
			Initials:     accountInitials(account.Name, account.Email),
			Current:      current,
			SignedIn:     signedIn,
			StatusText:   statusText,
			StatusTone:   statusTone,
			LastUsedText: lastUsedText,
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
