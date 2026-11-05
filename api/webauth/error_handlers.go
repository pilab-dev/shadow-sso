package webauth

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// NotFoundHandler renders a styled 404 page.
func (wa *WebAuth) NotFoundHandler(c *gin.Context) {
	c.HTML(http.StatusNotFound, "error.html", gin.H{
		"PageTitle": "Page not found",
		"Message":   "The page you are looking for could not be found.",
		"BrandName": wa.brandName(c),
	})
}

// MethodNotAllowedHandler renders a styled 405 page.
func (wa *WebAuth) MethodNotAllowedHandler(c *gin.Context) {
	c.HTML(http.StatusMethodNotAllowed, "error.html", gin.H{
		"PageTitle": "Method not allowed",
		"Message":   "The requested method is not allowed for this resource.",
		"BrandName": wa.brandName(c),
	})
}

// InternalServerErrorHandler renders a styled 500 page.
func (wa *WebAuth) InternalServerErrorHandler(c *gin.Context) {
	c.HTML(http.StatusInternalServerError, "error.html", gin.H{
		"PageTitle": "Server error",
		"Message":   "An unexpected error occurred. Please try again later.",
		"BrandName": wa.brandName(c),
	})
}
