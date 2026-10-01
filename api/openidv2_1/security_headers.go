package openidv2_1

import "github.com/gin-gonic/gin"

// SecurityHeadersMiddleware adds common security headers to responses.
//
// img-src allows data: URIs because the TOTP enrolment page embeds its QR code as a data URI;
// script-src stays 'self' (no inline scripts), so page scripts must be served from the SSO origin.
func SecurityHeadersMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; img-src 'self' data: https://fonts.gstatic.com; font-src 'self' https://fonts.googleapis.com https://fonts.gstatic.com; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'")
		c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		// Consider adding X-XSS-Protection, but it's largely superseded by CSP.
		// c.Header("X-XSS-Protection", "1; mode=block")
		// Referrer-Policy can also be useful.
		// c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		c.Next()
	}
}
