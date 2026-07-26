package ssosession

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
)

var ErrInvalidSession = errors.New("invalid sso_session cookie")

type Session struct {
	SessionID string    `json:"session_id"`
	Accounts  []Account `json:"accounts"`
	CSRFToken string   `json:"csrf_token"`
}

type Account struct {
	UserID   string    `json:"user_id"`
	Email    string    `json:"email"`
	Name     string    `json:"name"`
	Picture  string    `json:"picture,omitempty"`
	LastUsed time.Time `json:"last_used"`
}

const (
	CookieName   = "sso_session"
	MaxAge       = 30 * 24 * time.Hour
	CookieDomain = ".pilab.hu"
)

func SetCookie(w http.ResponseWriter, session *Session, isSecure bool, secret string) error {
	jsonBytes, err := json.Marshal(session)
	if err != nil {
		return err
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(jsonBytes)
	signature := mac.Sum(nil)

	encodedPayload := base64.RawURLEncoding.EncodeToString(jsonBytes)
	encodedSig := base64.RawURLEncoding.EncodeToString(signature)
	cookieValue := encodedPayload + "." + encodedSig

	sameSite := http.SameSiteLaxMode
	if isSecure {
		sameSite = http.SameSiteNoneMode
	}

	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    cookieValue,
		Domain:   CookieDomain,
		Path:     "/",
		MaxAge:   int(MaxAge.Seconds()),
		HttpOnly: true,
		Secure:   isSecure,
		SameSite: sameSite,
	})

	return nil
}

func VerifyAndDecode(cookieValue, secret string) (*Session, error) {
	if secret == "" {
		return nil, errors.New("sso_session cookie signing secret is not configured")
	}

	dotIdx := -1
	for i := len(cookieValue) - 1; i >= 0; i-- {
		if cookieValue[i] == '.' {
			dotIdx = i
			break
		}
	}
	if dotIdx < 0 {
		return nil, ErrInvalidSession
	}

	encodedPayload := cookieValue[:dotIdx]
	encodedSig := cookieValue[dotIdx+1:]

	jsonBytes, err := base64.RawURLEncoding.DecodeString(encodedPayload)
	if err != nil {
		return nil, ErrInvalidSession
	}

	sigBytes, err := base64.RawURLEncoding.DecodeString(encodedSig)
	if err != nil {
		return nil, ErrInvalidSession
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(jsonBytes)
	expectedSig := mac.Sum(nil)

	if subtle.ConstantTimeCompare(sigBytes, expectedSig) != 1 {
		return nil, ErrInvalidSession
	}

	var session Session
	if err := json.Unmarshal(jsonBytes, &session); err != nil {
		return nil, ErrInvalidSession
	}

	return &session, nil
}

func ParseFromCookieHeader(cookieHeader string) string {
	for _, part := range strings.Split(cookieHeader, ";") {
		part = strings.TrimSpace(part)
		if idx := strings.IndexByte(part, '='); idx >= 0 {
			name := part[:idx]
			value := part[idx+1:]
			if name == CookieName {
				return value
			}
		}
	}
	return ""
}

func NewID() string {
	return uuid.New().String()
}
