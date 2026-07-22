package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func mockHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

func TestGatewayExposeHandler(t *testing.T) {
	t.Parallel()
	handler := gatewayExposeHandler(mockHandler())

	tests := []struct {
		name           string
		body           string
		expectedStatus int
	}{
		{
			name:           "blocks unix protocol",
			body:           `{"local":"/tmp/test.sock","remote":"tcp://192.168.127.2:22","protocol":"unix"}`,
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "blocks npipe protocol",
			body:           `{"local":"//./pipe/test","remote":"tcp://192.168.127.2:22","protocol":"npipe"}`,
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "allows tcp protocol",
			body:           `{"local":":8080","remote":"192.168.127.2:80","protocol":"tcp"}`,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "allows udp protocol",
			body:           `{"local":":5353","remote":"192.168.127.2:53","protocol":"udp"}`,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "rejects invalid json",
			body:           `not json`,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "rejects empty body",
			body:           ``,
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/services/forwarder/expose", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			assert.Equal(t, tt.expectedStatus, rec.Code)
		})
	}
}

func TestGatewayExposeHandlerBlockMessage(t *testing.T) {
	t.Parallel()
	handler := gatewayExposeHandler(mockHandler())

	req := httptest.NewRequest(http.MethodPost, "/services/forwarder/expose",
		strings.NewReader(`{"local":"/tmp/test.sock","remote":"tcp://192.168.127.2:22","protocol":"unix"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Contains(t, rec.Body.String(), "unix and npipe protocols are not allowed")
}
