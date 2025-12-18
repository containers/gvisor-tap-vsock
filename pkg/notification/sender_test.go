package notification

import (
	"context"
	"encoding/json"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/containers/gvisor-tap-vsock/pkg/types"
	"github.com/stretchr/testify/assert"
)

func TestNewNotificationSender_EmptySocket(t *testing.T) {
	sender := NewNotificationSender("")
	assert.Nil(t, sender.notificationCh)
	assert.Empty(t, sender.socket)
}

func TestNewNotificationSender_NonEmptySocket(t *testing.T) {
	sender := NewNotificationSender("test.sock")
	assert.NotNil(t, sender)
	assert.Equal(t, "test.sock", sender.socket)
	assert.NotNil(t, sender.notificationCh)
}

func TestNotificationSender_NilChannel(t *testing.T) {
	sender := NewNotificationSender("")
	assert.Nil(t, sender.notificationCh)

	// should not panic
	sender.Send(types.NotificationMessage{
		NotificationType: types.ConnectionEstablished,
		MacAddress:       "5a:94:ef:e4:0c:ee",
	})
}

func TestNotificationSender_Success(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "test.sock")
	listener, err := net.Listen("unix", socketPath)
	assert.NoError(t, err)
	defer listener.Close()

	expectedNotifications := []types.NotificationMessage{
		{
			NotificationType: types.Ready,
		},
		{
			NotificationType: types.ConnectionEstablished,
			MacAddress:       "5a:94:ef:e4:0c:ee",
		},
		{
			NotificationType: types.HypervisorError,
		},
		{
			NotificationType: types.ConnectionClosed,
			MacAddress:       "5a:94:ef:e4:0c:ee",
		},
	}

	for _, expectedNotification := range expectedNotifications {
		t.Run(string(expectedNotification.NotificationType), func(t *testing.T) {
			done := make(chan struct{})
			go func() {
				defer close(done)
				conn, err := listener.Accept()
				assert.NoError(t, err)
				assert.NotNil(t, conn)
				defer conn.Close()

				dec := json.NewDecoder(conn)
				var notification types.NotificationMessage
				assert.NoError(t, dec.Decode(&notification))
				assert.Equal(t, expectedNotification.NotificationType, notification.NotificationType)
				assert.Equal(t, expectedNotification.MacAddress, notification.MacAddress)
			}()

			sender := NewNotificationSender(socketPath)
			go sender.Start(context.Background())

			sender.Send(expectedNotification)
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("timeout waiting for notification")
			}
		})
	}
}
