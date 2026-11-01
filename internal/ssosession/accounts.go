package ssosession

import "time"

// MaxAccounts is the maximum number of accounts kept in the login-UI session
// cookie. The most recently used account is always first.
const MaxAccounts = 5

// MergeAccount returns a session with account moved to the front. Existing
// metadata (name/email/picture) is preserved when the new account omits it.
// The existing session ID is reused so the UI session remains stable.
func MergeAccount(existing *Session, account Account) *Session {
	if account.LastUsed.IsZero() {
		account.LastUsed = time.Now()
	}

	session := &Session{SessionID: NewID()}
	if existing != nil {
		if existing.SessionID != "" {
			session.SessionID = existing.SessionID
		}
		for _, candidate := range existing.Accounts {
			if candidate.UserID != account.UserID {
				continue
			}
			if account.Email == "" {
				account.Email = candidate.Email
			}
			if account.Name == "" {
				account.Name = candidate.Name
			}
			if account.Picture == "" {
				account.Picture = candidate.Picture
			}
			break
		}
	}

	accounts := make([]Account, 0, MaxAccounts)
	accounts = append(accounts, account)
	if existing != nil {
		for _, candidate := range existing.Accounts {
			if candidate.UserID == account.UserID {
				continue
			}
			accounts = append(accounts, candidate)
			if len(accounts) == MaxAccounts {
				break
			}
		}
	}
	session.Accounts = accounts
	return session
}
