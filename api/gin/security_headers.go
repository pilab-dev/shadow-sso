package sssogin

import "github.com/gin-gonic/gin"

// SecurityHeadersMiddleware adds common security headers to responses.
func SecurityHeadersMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'self'")
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
