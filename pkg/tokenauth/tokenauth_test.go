package tokenauth

import (
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateToken(t *testing.T) {
	tests := []struct {
		name        string
		token       string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "Valid token (32 chars)",
			token:       "12345678901234567890123456789012",
			expectError: false,
		},
		{
			name:        "Valid token (44 chars, like GenerateToken)",
			token:       "xK8vN2Qp_7RmLwE4sJ9nY3Tc6Vh5Gz1Ua8Fb0Pd2Xe4=", //#nosec G101 -- test token, not real credential
			expectError: false,
		},
		{
			name:        "Valid token (256 chars, maximum)",
			token:       strings.Repeat("a", 256),
			expectError: false,
		},
		{
			name:        "Empty token",
			token:       "",
			expectError: true,
			errorMsg:    "too short",
		},
		{
			name:        "Token too short (31 chars)",
			token:       "1234567890123456789012345678901",
			expectError: true,
			errorMsg:    "too short",
		},
		{
			name:        "Token too short (10 chars)",
			token:       "1234567890",
			expectError: true,
			errorMsg:    "too short",
		},
		{
			name:        "Token too long (257 chars)",
			token:       strings.Repeat("a", 257),
			expectError: true,
			errorMsg:    "too long",
		},
		{
			name:        "Token too long (1000 chars)",
			token:       strings.Repeat("a", 1000),
			expectError: true,
			errorMsg:    "too long",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateToken(tt.token)

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
			}
		})
	}
}

func TestGenerateToken(t *testing.T) {
	// Generate multiple tokens
	token1, err := GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken() failed: %v", err)
	}

	token2, err := GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken() failed: %v", err)
	}

	// Tokens should be at least 32 characters (base64url of 32 bytes is 44 chars)
	if len(token1) < 32 {
		t.Errorf("Token too short: got %d characters, want at least 32", len(token1))
	}

	// Tokens should be different (not deterministic)
	if token1 == token2 {
		t.Errorf("Generated tokens are identical, expected unique tokens")
	}

	// Token should be valid base64url
	decoded, err := base64.URLEncoding.DecodeString(token1)
	if err != nil {
		t.Errorf("Token is not valid base64url: %v", err)
	}

	// Decoded token should be 32 bytes
	if len(decoded) != 32 {
		t.Errorf("Decoded token has wrong length: got %d bytes, want 32", len(decoded))
	}
}

func TestReadTokenFromFile_Whitespace(t *testing.T) {
	tmpDir := t.TempDir()
	tokenFile := filepath.Join(tmpDir, "token")

	// Write token with whitespace (32+ chars to pass length validation)
	validToken := "token-with-whitespace-minimum-32-chars"
	if err := os.WriteFile(tokenFile, []byte("  \n\t"+validToken+"\n\t  "), 0o600); err != nil {
		t.Fatalf("Failed to write token file: %v", err)
	}

	token, err := readTokenFromFile(tokenFile)
	if err != nil {
		t.Fatalf("readTokenFromFile() failed: %v", err)
	}

	if token != validToken {
		t.Errorf("readTokenFromFile() = %q, want %q", token, validToken)
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
			name:        "Valid permissions 0o600",
			permissions: 0o600,
			expectError: false,
		},
		{
			name:        "Invalid permissions 0o644",
			permissions: 0o644,
			expectError: true,
			errorMsg:    "insecure permissions",
		},
		{
			name:        "Invalid permissions 0o666",
			permissions: 0o666,
			expectError: true,
			errorMsg:    "insecure permissions",
		},
		{
			name:        "Invalid permissions 0o777",
			permissions: 0o777,
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

			token, err := readTokenFromFile(tokenFile)

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
		{
			name:        "Token too long (over 256 chars)",
			content:     strings.Repeat("a", 257),
			expectError: true,
			errorMsg:    "too long",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Write token file
			if err := os.WriteFile(tokenFile, []byte(tt.content), 0o600); err != nil {
				t.Fatalf("Failed to write token file: %v", err)
			}

			token, err := readTokenFromFile(tokenFile)

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
		{
			name:        "Token too long (over 256 chars)",
			envValue:    strings.Repeat("a", 257),
			want:        "",
			expectError: true,
			errorMsg:    "too long",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set environment variable
			if err := os.Setenv("GV_API_TOKEN", tt.envValue); err != nil {
				t.Fatalf("Failed to set environment variable: %v", err)
			}
			defer os.Unsetenv("GV_API_TOKEN")

			token, err := readTokenFromEnv()

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
					t.Errorf("readTokenFromEnv() = %q, want %q", token, tt.want)
				}
			}
		})
	}
}

func TestReadToken(t *testing.T) {
	tmpDir := t.TempDir()
	tokenFile := filepath.Join(tmpDir, "token")
	validToken := "this-is-a-valid-token-with-32-chars"

	tests := []struct {
		name        string
		setupFile   bool
		fileContent string
		envValue    string
		tokenFile   string
		want        string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "Token from file",
			setupFile:   true,
			fileContent: validToken,
			tokenFile:   tokenFile,
			want:        validToken,
			expectError: false,
		},
		{
			name:        "Token from env when no file specified",
			setupFile:   false,
			envValue:    validToken,
			tokenFile:   "",
			want:        validToken,
			expectError: false,
		},
		{
			name:        "File takes priority over env",
			setupFile:   true,
			fileContent: validToken,
			envValue:    "different-token-from-env-32chars",
			tokenFile:   tokenFile,
			want:        validToken,
			expectError: false,
		},
		{
			name:        "No token configured",
			setupFile:   false,
			envValue:    "",
			tokenFile:   "",
			want:        "",
			expectError: false,
		},
		{
			name:        "Invalid file returns error",
			setupFile:   false,
			tokenFile:   "/nonexistent/file",
			want:        "",
			expectError: true,
			errorMsg:    "failed to read API token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup file if needed
			if tt.setupFile {
				if err := os.WriteFile(tokenFile, []byte(tt.fileContent), 0o600); err != nil {
					t.Fatalf("Failed to write token file: %v", err)
				}
				defer os.Remove(tokenFile)
			}

			// Setup env if needed
			if tt.envValue != "" {
				if err := os.Setenv("GV_API_TOKEN", tt.envValue); err != nil {
					t.Fatalf("Failed to set environment variable: %v", err)
				}
				defer os.Unsetenv("GV_API_TOKEN")
			} else {
				os.Unsetenv("GV_API_TOKEN")
			}

			token, err := ReadToken(tt.tokenFile)

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
					t.Errorf("ReadToken() = %q, want %q", token, tt.want)
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
			name:           "Valid token with lowercase bearer",
			authHeader:     "bearer my-secret-token",
			expectedStatus: http.StatusOK,
			expectedBody:   "OK",
		},
		{
			name:           "Valid token with uppercase BEARER",
			authHeader:     "BEARER my-secret-token",
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
