package graphql_test

import (
	"testing"

	"github.com/pilab-dev/shadow-sso/domain"
	mock_domain "github.com/pilab-dev/shadow-sso/domain/mocks"
	"go.uber.org/mock/gomock"
)

func TestSetUserPassword_TemporaryAddsUpdatePassword(t *testing.T) {
	r := newTestResolver(t)
	userRepo := r.UserRepo.(*mock_domain.MockUserRepository)
	userRepo.EXPECT().GetUserByID(gomock.Any(), "u1").Return(&domain.User{ID: "u1"}, nil)
	userRepo.EXPECT().UpdateUser(gomock.Any(), gomock.Any()).DoAndReturn(func(_ any, u *domain.User) error {
		if !u.HasRequiredAction(domain.RequiredActionUpdatePassword) {
			t.Error("temporary password must flag UPDATE_PASSWORD")
		}
		return nil
	})
	if _, err := r.Mutation().SetUserPassword(adminCtx(), "u1", "tmp", true); err != nil {
		t.Fatal(err)
	}
}

func TestSetUserPassword_PermanentClearsUpdatePassword(t *testing.T) {
	r := newTestResolver(t)
	userRepo := r.UserRepo.(*mock_domain.MockUserRepository)
	userRepo.EXPECT().GetUserByID(gomock.Any(), "u1").Return(&domain.User{ID: "u1", RequiredActions: []string{domain.RequiredActionUpdatePassword}}, nil)
	userRepo.EXPECT().UpdateUser(gomock.Any(), gomock.Any()).DoAndReturn(func(_ any, u *domain.User) error {
		if u.HasRequiredAction(domain.RequiredActionUpdatePassword) {
			t.Error("permanent password must clear UPDATE_PASSWORD")
		}
		return nil
	})
	if _, err := r.Mutation().SetUserPassword(adminCtx(), "u1", "perm", false); err != nil {
		t.Fatal(err)
	}
}

func TestAddRemoveRequiredAction(t *testing.T) {
	r := newTestResolver(t)
	userRepo := r.UserRepo.(*mock_domain.MockUserRepository)

	userRepo.EXPECT().GetUserByID(gomock.Any(), "u1").Return(&domain.User{ID: "u1"}, nil)
	userRepo.EXPECT().UpdateUser(gomock.Any(), gomock.Any()).DoAndReturn(func(_ any, u *domain.User) error {
		if !u.HasRequiredAction(domain.RequiredActionConfigureTOTP) {
			t.Error("action not added")
		}
		return nil
	})
	if ok, err := r.Mutation().AddRequiredAction(adminCtx(), "u1", domain.RequiredActionConfigureTOTP); err != nil || !ok {
		t.Fatalf("add: ok=%v err=%v", ok, err)
	}

	if _, err := r.Mutation().AddRequiredAction(adminCtx(), "u1", "BOGUS"); err == nil {
		t.Fatal("unknown action must be rejected")
	}
	if _, err := r.Mutation().AddRequiredAction(userCtx(), "u1", domain.RequiredActionConfigureTOTP); err == nil {
		t.Fatal("non-admin must be denied")
	}

	userRepo.EXPECT().GetUserByID(gomock.Any(), "u1").Return(&domain.User{ID: "u1", RequiredActions: []string{domain.RequiredActionConfigureTOTP}}, nil)
	userRepo.EXPECT().UpdateUser(gomock.Any(), gomock.Any()).DoAndReturn(func(_ any, u *domain.User) error {
		if len(u.RequiredActions) != 0 {
			t.Error("action not removed")
		}
		return nil
	})
	if ok, err := r.Mutation().RemoveRequiredAction(adminCtx(), "u1", domain.RequiredActionConfigureTOTP); err != nil || !ok {
		t.Fatalf("remove: ok=%v err=%v", ok, err)
	}
	if _, err := r.Mutation().RemoveRequiredAction(userCtx(), "u1", domain.RequiredActionConfigureTOTP); err == nil {
		t.Fatal("non-admin must be denied")
	}
}
