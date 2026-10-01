package webauth

import (
	"net/http"
	"net/url"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pilab-dev/shadow-sso/domain"
	"github.com/rs/zerolog/log"
)

const emailVerificationTTL = 24 * time.Hour

// verifyEmailAction implements VERIFY_EMAIL. The action completes out of band when the
// user opens the emailed link (see VerifyEmailHandler); this page only sends/resends it.
type verifyEmailAction struct{}

func (verifyEmailAction) Render(c *gin.Context, wa *WebAuth, flowID string, user *domain.User, errMsg string) {
	info := ""
	expired := user.EmailVerificationTokenExpiresAt == nil || time.Now().After(*user.EmailVerificationTokenExpiresAt)
	if user.EmailVerificationToken == "" || expired {
		if err := wa.sendVerificationEmail(c, user); err != nil {
			log.Error().Err(err).Str("user_id", user.ID).Msg("verify email: send failed")
			errMsg = "We could not send the verification email. Please try again later."
		} else {
			info = "We sent a verification link to " + maskEmail(user.Email) + "."
		}
	} else if errMsg == "" {
		info = "A verification link was already sent to " + maskEmail(user.Email) + "."
	}
	wa.renderPage(c, "verify_email.html", "Verify your email", gin.H{
		"FlowID": flowID,
		"Error":  errMsg,
		"Info":   info,
	})
}

func (verifyEmailAction) Submit(c *gin.Context, wa *WebAuth, user *domain.User) (actionResult, error) {
	// The only POST is "resend".
	key := "verify-email:" + user.ID
	if !wa.rateLimiter.Allow(key) {
		return actionResult{Err: "Too many requests. Please try again later."}, nil
	}
	wa.rateLimiter.RecordFailure(key)
	if err := wa.sendVerificationEmail(c, user); err != nil {
		log.Error().Err(err).Str("user_id", user.ID).Msg("verify email: resend failed")
		return actionResult{Err: "We could not send the verification email. Please try again later."}, nil
	}
	wa.renderPage(c, "verify_email.html", "Verify your email", gin.H{
		"FlowID": c.PostForm("flow_id"),
		"Info":   "A new verification link was sent to " + maskEmail(user.Email) + ".",
	})
	return actionResult{Rendered: true}, nil
}

// sendVerificationEmail stores a fresh token digest on the user and emails the link.
func (wa *WebAuth) sendVerificationEmail(c *gin.Context, user *domain.User) error {
	token, digest, err := newEmailToken()
	if err != nil {
		return err
	}
	ctx := c.Request.Context()
	if err := wa.userRepo.StoreEmailVerificationToken(ctx, user.ID, digest, time.Now().Add(emailVerificationTTL)); err != nil {
		return err
	}
	expires := time.Now().Add(emailVerificationTTL)
	user.EmailVerificationToken, user.EmailVerificationTokenExpiresAt = digest, &expires
	link := wa.baseURL(c) + "/verify-email?token=" + url.QueryEscape(token)
	return wa.emailService.SendVerificationEmail(user.Email, displayName(user), link)
}

// VerifyEmailHandler serves GET /verify-email?token=...: the target of the emailed link.
func (wa *WebAuth) VerifyEmailHandler(c *gin.Context) {
	ctx := c.Request.Context()
	token := c.Query("token")
	if token == "" {
		wa.renderMessage(c, http.StatusBadRequest, "Invalid link", "This verification link is invalid.", "", "")
		return
	}
	user, err := wa.userRepo.GetUserByEmailVerificationToken(ctx, hashEmailToken(token))
	if err != nil || user == nil || user.EmailVerificationTokenExpiresAt == nil || time.Now().After(*user.EmailVerificationTokenExpiresAt) {
		wa.renderMessage(c, http.StatusBadRequest, "Link expired", "This verification link is invalid or has expired. Sign in again to request a new one.", "/login", "Go to sign in")
		return
	}
	user.IsEmailVerified = true
	user.EmailVerificationToken, user.EmailVerificationTokenExpiresAt = "", nil
	user.RemoveRequiredAction(domain.RequiredActionVerifyEmail)
	if err := wa.userRepo.UpdateUser(ctx, user); err != nil {
		log.Error().Err(err).Str("user_id", user.ID).Msg("verify email: persist failed")
		wa.renderInternalError(c, "Could not verify your email. Please try again.")
		return
	}
	log.Info().Str("user_id", user.ID).Msg("email verified")
	wa.renderMessage(c, http.StatusOK, "Email verified", "Your email address is verified. You can close this tab and continue where you left off, or sign in again.", "/login", "Continue")
}

// ---- shared helpers -------------------------------------------------------------------------

func displayName(user *domain.User) string {
	if user.FirstName != "" || user.LastName != "" {
		return user.FirstName + " " + user.LastName
	}
	return user.Email
}

// baseURL returns the configured public origin or, failing that, the request's own origin.
func (wa *WebAuth) baseURL(c *gin.Context) string {
	if wa.publicBaseURL != "" {
		return wa.publicBaseURL
	}
	scheme := "http"
	if IsSecureRequest(c.Request) {
		scheme = "https"
	}
	return scheme + "://" + c.Request.Host
}

// renderPage renders a branded template with a fresh CSRF token merged into data.
func (wa *WebAuth) renderPage(c *gin.Context, tmpl, title string, data gin.H) {
	csrfToken, err := generateCSRFToken()
	if err != nil {
		wa.renderInternalError(c, "Internal error. Please try again.")
		return
	}
	setCSRFCookie(c.Writer, csrfToken, 10*time.Minute, IsSecureRequest(c.Request))
	data["PageTitle"] = title
	data["CSRFToken"] = csrfToken
	data["BrandName"] = wa.brandName(c)
	status := http.StatusOK
	if e, _ := data["Error"].(string); e != "" {
		status = http.StatusUnprocessableEntity
	}
	c.HTML(status, tmpl, data)
}

// renderMessage renders a terminal message page with an optional link.
func (wa *WebAuth) renderMessage(c *gin.Context, status int, title, message, linkURL, linkText string) {
	c.HTML(status, "message.html", gin.H{
		"PageTitle": title,
		"Title":     title,
		"Message":   message,
		"LinkURL":   linkURL,
		"LinkText":  linkText,
		"BrandName": wa.brandName(c),
	})
}
