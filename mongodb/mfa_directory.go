package mongodb

import (
	"context"
	"errors"
	"time"

	"github.com/pilab-dev/shadow-sso/domain"
)

func timeNow() time.Time { return time.Now() }

// MongoMFADirectory implements domain.MFADirectory backed by the users collection.
// It keeps MFA method records embedded in the user document, which keeps the
// storage modular and lets a future (non-LDAP) directory server replace it
// without touching any provider code.
type MongoMFADirectory struct {
	repo domain.UserRepository
}

func NewMongoMFADirectory(repo domain.UserRepository) *MongoMFADirectory {
	return &MongoMFADirectory{repo: repo}
}

func (d *MongoMFADirectory) GetUser(ctx context.Context, userID string) (*domain.User, error) {
	return d.repo.GetUserByID(ctx, userID)
}

func (d *MongoMFADirectory) AddMethod(ctx context.Context, userID string, method *domain.MfaMethod) error {
	user, err := d.repo.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}
	user.MfaMethods = append(user.MfaMethods, *method)
	user.UpdatedAt = timeNow()
	return d.repo.UpdateUser(ctx, user)
}

func (d *MongoMFADirectory) GetMethod(ctx context.Context, userID, methodID string) (*domain.MfaMethod, error) {
	user, err := d.repo.GetUserByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	for i := range user.MfaMethods {
		if user.MfaMethods[i].ID == methodID {
			m := user.MfaMethods[i]
			return &m, nil
		}
	}
	return nil, errors.New("mfa method not found")
}

func (d *MongoMFADirectory) ListMethods(ctx context.Context, userID string) ([]domain.MfaMethod, error) {
	user, err := d.repo.GetUserByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	return user.MfaMethods, nil
}

func (d *MongoMFADirectory) UpdateMethod(ctx context.Context, userID string, method *domain.MfaMethod) error {
	user, err := d.repo.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}
	for i := range user.MfaMethods {
		if user.MfaMethods[i].ID == method.ID {
			user.MfaMethods[i] = *method
			user.UpdatedAt = timeNow()
			return d.repo.UpdateUser(ctx, user)
		}
	}
	return errors.New("mfa method not found")
}

func (d *MongoMFADirectory) DeleteMethod(ctx context.Context, userID, methodID string) error {
	user, err := d.repo.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}
	out := user.MfaMethods[:0]
	for _, m := range user.MfaMethods {
		if m.ID != methodID {
			out = append(out, m)
		}
	}
	user.MfaMethods = out
	user.UpdatedAt = timeNow()
	return d.repo.UpdateUser(ctx, user)
}

func (d *MongoMFADirectory) FindByCredentialID(ctx context.Context, credentialID string) (*domain.User, *domain.MfaMethod, error) {
	pageToken := ""
	for {
		users, next, err := d.repo.ListUsers(ctx, pageToken, 100)
		if err != nil {
			return nil, nil, err
		}
		for _, u := range users {
			for _, dev := range u.WebAuthnDevices {
				if dev.CredentialID == credentialID {
					for i := range u.MfaMethods {
						if u.MfaMethods[i].Type == domain.MfaMethodTypeWebAuthn {
							m := u.MfaMethods[i]
							return u, &m, nil
						}
					}
					return u, nil, nil
				}
			}
		}
		if next == "" {
			break
		}
		pageToken = next
	}
	return nil, nil, domain.ErrUserNotFound
}
