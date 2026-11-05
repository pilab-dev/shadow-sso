package services

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/golang-jwt/jwt/v5"
	"github.com/pilab-dev/shadow-sso/domain"
	mock_domain "github.com/pilab-dev/shadow-sso/domain/mocks"
	ssov1 "github.com/pilab-dev/shadow-sso/gen/proto/sso/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestRealmService_UpdateRealmPartial(t *testing.T) {
	ctrl := gomock.NewController(t)
	settingsRepo := mock_domain.NewMockRealmSettingsRepository(ctrl)
	settingsRepo.EXPECT().GetRealmSettings(gomock.Any()).Return(&domain.RealmSettings{
		Realm: "master", DisplayName: "Old", Enabled: true, SSLRequired: "external",
	}, nil)
	settingsRepo.EXPECT().UpdateRealmSettings(gomock.Any(), gomock.Any()).Return(nil)
	server := NewRealmServer(settingsRepo, mock_domain.NewMockRealmKeysRepository(ctrl))

	resp, err := server.UpdateRealm(context.Background(), connect.NewRequest(&ssov1.UpdateRealmRequest{
		DisplayName:         ptr("New"),
		RegistrationAllowed: ptr(true),
	}))
	require.NoError(t, err)
	assert.Equal(t, "New", resp.Msg.Realm.DisplayName)
	assert.True(t, resp.Msg.Realm.RegistrationAllowed)
	assert.True(t, resp.Msg.Realm.Enabled)
	assert.Equal(t, "external", resp.Msg.Realm.SslRequired)
}

func TestRealmService_UpdateRealmRejectsBadSSL(t *testing.T) {
	ctrl := gomock.NewController(t)
	server := NewRealmServer(mock_domain.NewMockRealmSettingsRepository(ctrl), mock_domain.NewMockRealmKeysRepository(ctrl))
	_, err := server.UpdateRealm(context.Background(), connect.NewRequest(&ssov1.UpdateRealmRequest{SslRequired: ptr("sometimes")}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
}

func TestRealmService_GetRealmNotFound(t *testing.T) {
	ctrl := gomock.NewController(t)
	settingsRepo := mock_domain.NewMockRealmSettingsRepository(ctrl)
	settingsRepo.EXPECT().GetRealmSettings(gomock.Any()).Return(nil, errors.New("realm settings not found"))
	server := NewRealmServer(settingsRepo, mock_domain.NewMockRealmKeysRepository(ctrl))
	_, err := server.GetRealm(context.Background(), connect.NewRequest(&ssov1.GetRealmRequest{}))
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))
}

func TestRealmService_Keys(t *testing.T) {
	ctrl := gomock.NewController(t)
	keysRepo := mock_domain.NewMockRealmKeysRepository(ctrl)
	keysRepo.EXPECT().UpdateRealmKeys(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, keys []*domain.RealmKey) error {
		require.Len(t, keys, 1)
		assert.Equal(t, "rsa-1", keys[0].Name)
		assert.True(t, keys[0].Active)
		keys[0].ID = "k1"
		return nil
	})
	keysRepo.EXPECT().ListRealmKeys(gomock.Any()).Return([]*domain.RealmKey{{ID: "k1", Name: "rsa-1", PrivateKey: "secret"}}, nil)
	server := NewRealmServer(mock_domain.NewMockRealmSettingsRepository(ctrl), keysRepo)

	up, err := server.UpdateRealmKeys(context.Background(), connect.NewRequest(&ssov1.UpdateRealmKeysRequest{
		Keys: []*ssov1.RealmKeyInput{{Name: "rsa-1", Type: "RSA", ProviderId: "rsa", Active: true, Priority: 100}},
	}))
	require.NoError(t, err)
	assert.Equal(t, "k1", up.Msg.Keys[0].Id)

	list, err := server.ListRealmKeys(context.Background(), connect.NewRequest(&ssov1.ListRealmKeysRequest{}))
	require.NoError(t, err)
	require.Len(t, list.Msg.Keys, 1)

	_, err = server.UpdateRealmKeys(context.Background(), connect.NewRequest(&ssov1.UpdateRealmKeysRequest{
		Keys: []*ssov1.RealmKeyInput{{Name: "x"}},
	}))
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
}

func TestRealmService_GenerateRealmKeyIsUsableBySigner(t *testing.T) {
	encKey := bytes.Repeat([]byte("k"), 32)
	for _, keyType := range []string{"ES256", "EdDSA", "PS256"} {
		ctrl := gomock.NewController(t)
		keysRepo := mock_domain.NewMockRealmKeysRepository(ctrl)
		var saved *domain.RealmKey
		keysRepo.EXPECT().SaveRealmKey(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, k *domain.RealmKey) error {
			saved = k
			return nil
		})
		server := NewRealmServer(mock_domain.NewMockRealmSettingsRepository(ctrl), keysRepo).WithKeyGeneration(encKey, nil)

		resp, err := server.GenerateRealmKey(context.Background(), connect.NewRequest(&ssov1.GenerateRealmKeyRequest{Name: "k", Type: keyType, Priority: 1}))
		require.NoError(t, err, keyType)
		assert.NotEmpty(t, saved.PublicKey, keyType)
		assert.Equal(t, saved.ID, resp.Msg.Key.Id)

		signer := NewTokenSigner()
		keysRepo.EXPECT().ListAllKeys(gomock.Any()).Return([]*domain.RealmKey{saved}, nil)
		require.NoError(t, signer.LoadFromRepository(context.Background(), keysRepo, encKey))
		tok, err := signer.Sign(jwt.MapClaims{"sub": "u", "exp": time.Now().Add(time.Minute).Unix()}, "")
		require.NoError(t, err, keyType)
		_, err = signer.VerifyAsymmetricToken(tok)
		require.NoError(t, err, keyType)
	}

	server := NewRealmServer(nil, nil).WithKeyGeneration(encKey, nil)
	_, err := server.GenerateRealmKey(context.Background(), connect.NewRequest(&ssov1.GenerateRealmKeyRequest{Name: "k", Type: "HS256"}))
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
}
