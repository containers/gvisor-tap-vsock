package virtualnetwork

import (
	"crypto/subtle"
	"fmt"
	"net/http"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"
)

// ReadTokenFromFile reads the token from a file and validates file permissions and token format
func ReadTokenFromFile(filepath string) (string, error) {
	info, err := os.Stat(filepath)
	if err != nil {
		return "", fmt.Errorf("failed to stat token file: %w", err)
	}

	if perm := info.Mode().Perm(); perm != 0600 {
		return "", fmt.Errorf("token file has insecure permissions %o (must be 0600)", perm)
	}

	data, err := os.ReadFile(filepath)
	if err != nil {
		return "", fmt.Errorf("failed to read token file: %w", err)
	}
	token := strings.TrimSpace(string(data))
	if token == "" {
		return "", fmt.Errorf("token file is empty")
	}
	if len(token) < 32 {
		return "", fmt.Errorf("token is too short (%d characters, minimum 32 required)", len(token))
	}

	return token, nil
}

// ReadTokenFromEnv reads the token from the GVISOR_API_TOKEN environment variable
// Returns empty string and no error if the environment variable is not set
// Returns error if the token is set but invalid (too short)
func ReadTokenFromEnv() (string, error) {
	token := strings.TrimSpace(os.Getenv("GVISOR_API_TOKEN"))
	if token == "" {
		// Empty token means "no token configured"
		return "", nil
	}
	if len(token) < 32 {
		return "", fmt.Errorf("GVISOR_API_TOKEN is too short (%d characters, minimum 32 required)", len(token))
	}
	return token, nil
}

// BearerAuthMiddleware creates middleware that validates Bearer token authentication
// If expectedToken is empty, the middleware allows all requests (backwards compatibility)
func BearerAuthMiddleware(expectedToken string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// If no token is configured, allow all requests (backwards compatibility)
			if expectedToken == "" {
				log.Debug("No API token configured, allowing unauthenticated request")
				next.ServeHTTP(w, r)
				return
			}

			// Extract Authorization header
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				log.Warnf("API request from %s denied: missing Authorization header", r.RemoteAddr)
				http.Error(w, "Authorization required", http.StatusUnauthorized)
				return
			}

			// Check Bearer scheme
			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) != 2 || parts[0] != "Bearer" {
				log.Warnf("API request from %s denied: invalid Authorization scheme", r.RemoteAddr)
				http.Error(w, "Invalid authorization header format. Expected: Bearer <token>", http.StatusUnauthorized)
				return
			}

			providedToken := parts[1]

			// Use constant-time comparison to prevent timing attacks
			if subtle.ConstantTimeCompare([]byte(providedToken), []byte(expectedToken)) != 1 {
				log.Warnf("API request from %s denied: invalid token", r.RemoteAddr)
				http.Error(w, "Invalid token", http.StatusUnauthorized)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
