package notifications

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFirebaseUnconfiguredReturnsError(t *testing.T) {
	s := NewFirebasePushService("", "")
	require.ErrorIs(t, s.SendPushNotification("tok", "t", "b", nil), ErrPushNotConfigured)
	require.ErrorIs(t, s.SendMFAPushChallenge("tok", "c", "1.1.1.1", "ua"), ErrPushNotConfigured)
	require.ErrorIs(t, s.SendPushNotificationToUser("u", "t", "b", nil), ErrPushNotConfigured)
}

func TestFirebaseSendPostsMessage(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got = string(b)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s := &FirebasePushService{client: srv.Client(), sendURL: srv.URL}
	require.NoError(t, s.SendPushNotification("device-1", "Hi", "Body", map[string]interface{}{"n": 1}))
	require.Contains(t, got, `"token":"device-1"`)
	require.Contains(t, got, `"message"`)

	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusUnauthorized) }))
	defer bad.Close()
	s = &FirebasePushService{client: bad.Client(), sendURL: bad.URL}
	require.Error(t, s.SendPushNotification("d", "t", "b", nil))
}
