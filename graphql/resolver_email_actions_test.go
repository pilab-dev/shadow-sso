package graphql_test

import (
	"strings"
	"testing"
	"time"

	"github.com/pilab-dev/shadow-sso/domain"
	mock_domain "github.com/pilab-dev/shadow-sso/domain/mocks"
	pkgauth "github.com/pilab-dev/shadow-sso/pkg/auth"
	"go.uber.org/mock/gomock"
)

func TestSendPasswordResetEmail_StoresDigestAndEmailsRedeemableLink(t *testing.T) {
	r := newTestResolver(t)
	ctrl := gomock.NewController(t)
	mail := mock_domain.NewMockEmailService(ctrl)
	r.EmailService = mail
	r.PublicBaseURL = "https://sso.test"
	userRepo := r.UserRepo.(*mock_domain.MockUserRepository)
	userRepo.EXPECT().GetUserByID(gomock.Any(), "u1").Return(&domain.User{ID: "u1", Email: "a@b.c", FirstName: "Ann"}, nil)

	var digest string
	userRepo.EXPECT().StorePasswordResetToken(gomock.Any(), "u1", gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ any, _ string, d string, exp time.Time) error { digest = d; return nil })
	var link string
	mail.EXPECT().SendPasswordResetEmail("a@b.c", "Ann", gomock.Any()).DoAndReturn(func(_, _, l string) error { link = l; return nil })

	ok, err := r.Mutation().SendPasswordResetEmail(adminCtx(), "u1")
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	const prefix = "https://sso.test/reset-password?token="
	if !strings.HasPrefix(link, prefix) {
		t.Fatalf("link = %q, want prefix %q (never a placeholder host)", link, prefix)
	}
	if got := pkgauth.HashEmailToken(strings.TrimPrefix(link, prefix)); got != digest {
		t.Fatalf("stored digest %q does not match the emailed token (%q)", digest, got)
	}
}

func TestSendEmails_RequireAdminAndConfiguredMailer(t *testing.T) {
	r := newTestResolver(t)
	if _, err := r.Mutation().SendPasswordResetEmail(userCtx(), "u1"); err == nil {
		t.Fatal("non-admin must be denied")
	}
	if _, err := r.Mutation().SendVerificationEmail(userCtx(), "u1"); err == nil {
		t.Fatal("non-admin must be denied")
	}
	if _, err := r.Mutation().SendPasswordResetEmail(noTokenCtx(), "u1"); err == nil {
		t.Fatal("unauthenticated must be denied")
	}
	r.EmailService = nil
	if _, err := r.Mutation().SendVerificationEmail(adminCtx(), "u1"); err == nil {
		t.Fatal("missing mail provider must be reported")
	}
}

func TestSendVerificationEmail_LinkPointsAtVerifyEmail(t *testing.T) {
	r := newTestResolver(t)
	ctrl := gomock.NewController(t)
	mail := mock_domain.NewMockEmailService(ctrl)
	r.EmailService = mail
	r.PublicBaseURL = "https://sso.test"
	userRepo := r.UserRepo.(*mock_domain.MockUserRepository)
	userRepo.EXPECT().GetUserByID(gomock.Any(), "u1").Return(&domain.User{ID: "u1", Email: "a@b.c"}, nil)
	userRepo.EXPECT().StoreEmailVerificationToken(gomock.Any(), "u1", gomock.Any(), gomock.Any()).Return(nil)
	mail.EXPECT().SendVerificationEmail("a@b.c", gomock.Any(), gomock.Regex(`^https://sso\.test/verify-email\?token=[A-Za-z0-9_-]{43}$`)).Return(nil)
	if ok, err := r.Mutation().SendVerificationEmail(adminCtx(), "u1"); err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
}

func TestExecuteActions_SetsRequiredActions(t *testing.T) {
	r := newTestResolver(t)
	userRepo := r.UserRepo.(*mock_domain.MockUserRepository)
	userRepo.EXPECT().GetUserByID(gomock.Any(), "u1").Return(&domain.User{ID: "u1"}, nil)
	userRepo.EXPECT().UpdateUser(gomock.Any(), gomock.Any()).DoAndReturn(func(_ any, u *domain.User) error {
		if !u.HasRequiredAction(domain.RequiredActionUpdatePassword) || !u.HasRequiredAction(domain.RequiredActionConfigureTOTP) {
			t.Errorf("actions not applied: %v", u.RequiredActions)
		}
		return nil
	})
	ok, err := r.Mutation().ExecuteActions(adminCtx(), "u1", []string{domain.RequiredActionUpdatePassword, domain.RequiredActionConfigureTOTP})
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	if _, err := r.Mutation().ExecuteActions(adminCtx(), "u1", []string{"BOGUS"}); err == nil {
		t.Fatal("unknown action must be rejected")
	}
	if _, err := r.Mutation().ExecuteActions(userCtx(), "u1", []string{domain.RequiredActionTerms}); err == nil {
		t.Fatal("non-admin must be denied")
	}
}
