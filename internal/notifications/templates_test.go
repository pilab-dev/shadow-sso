package notifications

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRenderEmailTemplate_Embedded(t *testing.T) {
	cases := []struct {
		name string
		data emailTemplateData
		want string
	}{
		{"verification.html", emailTemplateData{Name: "Alice", Link: "https://x/verify"}, "https://x/verify"},
		{"password_reset.html", emailTemplateData{Name: "Bob", Link: "https://x/reset"}, "https://x/reset"},
		{"otp.html", emailTemplateData{OTP: "123456"}, "123456"},
		{"mfa.html", emailTemplateData{Name: "Carol", OTP: "654321", Method: "EMAIL"}, "654321"},
	}
	for _, tc := range cases {
		out, err := renderEmailTemplate(tc.name, tc.data, nil)
		require.NoError(t, err, tc.name)
		assert.Contains(t, out, tc.want, tc.name)
	}
}

func TestSMTPEmailService_IsConfigured(t *testing.T) {
	assert.False(t, NewSMTPEmailService("", "", "", "", "", "").IsConfigured())
	assert.True(t, NewSMTPEmailService("pimail.local", "587", "", "", "noreply@example.com", "").IsConfigured())
}