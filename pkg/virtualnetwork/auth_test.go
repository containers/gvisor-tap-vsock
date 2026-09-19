package virtualnetwork

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadTokenFromFile_Whitespace(t *testing.T) {
	tmpDir := t.TempDir()
	tokenFile := filepath.Join(tmpDir, "token")

	// Write token with whitespace (32+ chars to pass length validation)
	validToken := "token-with-whitespace-minimum-32-chars"
	if err := os.WriteFile(tokenFile, []byte("  \n\t"+validToken+"\n\t  "), 0600); err != nil {
		t.Fatalf("Failed to write token file: %v", err)
	}

	token, err := ReadTokenFromFile(tokenFile)
	if err != nil {
		t.Fatalf("ReadTokenFromFile() failed: %v", err)
	}

	if token != validToken {
		t.Errorf("ReadTokenFromFile() = %q, want %q", token, validToken)
	}
}

func TestReadTokenFromFile_Permissions(t *testing.T) {
	tmpDir := t.TempDir()
	tokenFile := filepath.Join(tmpDir, "token")
	validToken := "this-is-a-valid-token-with-32-chars-minimum"

	tests := []struct {
		name        string
		permissions os.FileMode
		expectError bool
		errorMsg    string
	}{
		{
			name:        "Valid permissions 0600",
			permissions: 0600,
			expectError: false,
		},
		{
			name:        "Invalid permissions 0644",
			permissions: 0644,
			expectError: true,
			errorMsg:    "insecure permissions",
		},
		{
			name:        "Invalid permissions 0666",
			permissions: 0666,
			expectError: true,
			errorMsg:    "insecure permissions",
		},
		{
			name:        "Invalid permissions 0777",
			permissions: 0777,
			expectError: true,
			errorMsg:    "insecure permissions",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Write file with specific permissions
			if err := os.WriteFile(tokenFile, []byte(validToken), tt.permissions); err != nil {
				t.Fatalf("Failed to write token file: %v", err)
			}

			token, err := ReadTokenFromFile(tokenFile)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error containing %q, got nil", tt.errorMsg)
				} else if !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("Expected error containing %q, got %q", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if token != validToken {
					t.Errorf("Got token %q, want %q", token, validToken)
				}
			}

			// Clean up for next test
			os.Remove(tokenFile)
		})
	}
}

func TestReadTokenFromFile_Validation(t *testing.T) {
	tmpDir := t.TempDir()
	tokenFile := filepath.Join(tmpDir, "token")

	tests := []struct {
		name        string
		content     string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "Valid token",
			content:     "this-is-a-valid-32-character-token-here",
			expectError: false,
		},
		{
			name:        "Empty file",
			content:     "",
			expectError: true,
			errorMsg:    "empty",
		},
		{
			name:        "Whitespace only",
			content:     "   \n\t   ",
			expectError: true,
			errorMsg:    "empty",
		},
		{
			name:        "Token too short",
			content:     "short",
			expectError: true,
			errorMsg:    "too short",
		},
		{
			name:        "Token exactly 32 chars",
			content:     "12345678901234567890123456789012",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Write token file
			if err := os.WriteFile(tokenFile, []byte(tt.content), 0600); err != nil {
				t.Fatalf("Failed to write token file: %v", err)
			}

			token, err := ReadTokenFromFile(tokenFile)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error containing %q, got nil", tt.errorMsg)
				} else if !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("Expected error containing %q, got %q", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				expectedToken := strings.TrimSpace(tt.content)
				if token != expectedToken {
					t.Errorf("Got token %q, want %q", token, expectedToken)
				}
			}
		})
	}
}

func TestReadTokenFromEnv(t *testing.T) {
	tests := []struct {
		name        string
		envValue    string
		want        string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "Valid token",
			envValue:    "my-env-token-with-minimum-32-chars",
			want:        "my-env-token-with-minimum-32-chars",
			expectError: false,
		},
		{
			name:        "Valid token with whitespace",
			envValue:    "  \n\tmy-env-token-with-minimum-32-chars\n\t  ",
			want:        "my-env-token-with-minimum-32-chars",
			expectError: false,
		},
		{
			name:        "Empty token returns empty (no error)",
			envValue:    "",
			want:        "",
			expectError: false,
		},
		{
			name:        "Whitespace only returns empty (no error)",
			envValue:    "  \n\t  ",
			want:        "",
			expectError: false,
		},
		{
			name:        "Too short token returns error",
			envValue:    "short",
			want:        "",
			expectError: true,
			errorMsg:    "too short",
		},
		{
			name:        "Exactly 32 chars is valid",
			envValue:    "12345678901234567890123456789012",
			want:        "12345678901234567890123456789012",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set environment variable
			if err := os.Setenv("GVISOR_API_TOKEN", tt.envValue); err != nil {
				t.Fatalf("Failed to set environment variable: %v", err)
			}
			defer os.Unsetenv("GVISOR_API_TOKEN")

			token, err := ReadTokenFromEnv()

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error containing %q, got nil", tt.errorMsg)
				} else if !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("Expected error containing %q, got %q", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if token != tt.want {
					t.Errorf("ReadTokenFromEnv() = %q, want %q", token, tt.want)
				}
			}
		})
	}
}

func TestBearerAuthMiddleware_NoToken(t *testing.T) {
	// When no token is configured, all requests should be allowed
	handler := BearerAuthMiddleware("")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	}))

	tests := []struct {
		name   string
		header string
	}{
		{"No auth header", ""},
		{"With auth header", "Bearer some-token"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test", nil)
			if tt.header != "" {
				req.Header.Set("Authorization", tt.header)
			}

			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Errorf("Expected status 200, got %d", w.Code)
			}

			body, _ := io.ReadAll(w.Body)
			if string(body) != "OK" {
				t.Errorf("Expected body 'OK', got %q", string(body))
			}
		})
	}
}

func TestBearerAuthMiddleware_WithToken(t *testing.T) {
	expectedToken := "my-secret-token"

	handler := BearerAuthMiddleware(expectedToken)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	}))

	tests := []struct {
		name           string
		authHeader     string
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "Valid token",
			authHeader:     "Bearer my-secret-token",
			expectedStatus: http.StatusOK,
			expectedBody:   "OK",
		},
		{
			name:           "Missing auth header",
			authHeader:     "",
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   "Authorization required\n",
		},
		{
			name:           "Invalid scheme",
			authHeader:     "Basic my-secret-token",
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   "Invalid authorization header format. Expected: Bearer <token>\n",
		},
		{
			name:           "Wrong token",
			authHeader:     "Bearer wrong-token",
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   "Invalid token\n",
		},
		{
			name:           "Malformed header",
			authHeader:     "BearerNoSpace",
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   "Invalid authorization header format. Expected: Bearer <token>\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test", nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}

			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
			}

			body, _ := io.ReadAll(w.Body)
			if string(body) != tt.expectedBody {
				t.Errorf("Expected body %q, got %q", tt.expectedBody, string(body))
			}
		})
	}
}
