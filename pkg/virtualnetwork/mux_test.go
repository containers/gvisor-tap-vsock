package virtualnetwork

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/containers/gvisor-tap-vsock/pkg/types"
)

const testAPIToken = "synthetic-test-api-token-000000000000000000000000"

func newPolicyReloadTestNetwork(t *testing.T) *VirtualNetwork {
	t.Helper()
	holder, err := types.NewEgressPolicyHolder(&types.EgressPolicy{
		Revision: "r1",
		Allow: []types.EgressRule{{
			Protocol: "tcp",
			CIDR:     "192.0.2.0/24",
		}},
	}, true)
	if err != nil {
		t.Fatalf("create policy holder: %v", err)
	}
	t.Cleanup(func() {
		if err := holder.Close(); err != nil {
			t.Errorf("close policy holder: %v", err)
		}
	})
	return &VirtualNetwork{egressPolicy: holder, apiToken: testAPIToken}
}

func TestServicesMuxAuthenticatesPolicyReload(t *testing.T) {
	network := newPolicyReloadTestNetwork(t)
	loadCount := 0
	network.SetEgressPolicyLoader(func() (*types.EgressPolicy, error) {
		loadCount++
		return &types.EgressPolicy{
			Revision: "r2",
			Allow: []types.EgressRule{{
				Protocol: "tcp",
				CIDR:     "198.51.100.0/24",
			}},
		}, nil
	})
	handler := network.ServicesMux()

	for _, test := range []struct {
		name  string
		token string
	}{
		{name: "missing token"},
		{name: "wrong token", token: "wrong-token"},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/egress-policy/reload", nil)
			if test.token != "" {
				request.Header.Set("Authorization", "Bearer "+test.token)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want %d", response.Code, http.StatusUnauthorized)
			}
		})
	}
	if loadCount != 0 {
		t.Fatalf("unauthorized requests invoked policy loader %d times", loadCount)
	}
	request := httptest.NewRequest(http.MethodGet, "/stats", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated services API status = %d, want %d", response.Code, http.StatusUnauthorized)
	}

	request = httptest.NewRequest(http.MethodPost, "/egress-policy/reload", nil)
	request.Header.Set("Authorization", "Bearer "+testAPIToken)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("authenticated status = %d, want %d: %s", response.Code, http.StatusOK, response.Body.String())
	}
	var result struct {
		Revision string `json:"revision"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if result.Revision != "r2" || network.EgressPolicyRevision() != "r2" {
		t.Fatalf("reload revision = response %q, active %q; want r2", result.Revision, network.EgressPolicyRevision())
	}
}

func TestServicesMuxPolicyReloadRejectsInvalidUpdate(t *testing.T) {
	network := newPolicyReloadTestNetwork(t)
	network.SetEgressPolicyLoader(func() (*types.EgressPolicy, error) {
		return &types.EgressPolicy{
			Revision: "bad",
			Allow:    []types.EgressRule{{Protocol: "tcp", CIDR: "invalid"}},
		}, nil
	})
	request := httptest.NewRequest(http.MethodPost, "/egress-policy/reload", nil)
	request.Header.Set("Authorization", "Bearer "+testAPIToken)
	response := httptest.NewRecorder()
	network.ServicesMux().ServeHTTP(response, request)
	if response.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want %d: %s", response.Code, http.StatusUnprocessableEntity, response.Body.String())
	}
	if revision := network.EgressPolicyRevision(); revision != "r1" {
		t.Fatalf("failed reload replaced active revision with %q", revision)
	}
}

func TestServicesMuxPolicyReloadMethodAndAvailability(t *testing.T) {
	network := newPolicyReloadTestNetwork(t)
	handler := network.ServicesMux()

	request := httptest.NewRequest(http.MethodGet, "/egress-policy/reload", nil)
	request.Header.Set("Authorization", "Bearer "+testAPIToken)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusMethodNotAllowed || response.Header().Get("Allow") != http.MethodPost {
		t.Fatalf("GET status/Allow = %d/%q, want 405/POST", response.Code, response.Header().Get("Allow"))
	}

	request = httptest.NewRequest(http.MethodPost, "/egress-policy/reload", strings.NewReader("ignored"))
	request.Header.Set("Authorization", "Bearer "+testAPIToken)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("request with body status = %d, want %d", response.Code, http.StatusBadRequest)
	}

	request = httptest.NewRequest(http.MethodPost, "/egress-policy/reload", nil)
	request.Header.Set("Authorization", "Bearer "+testAPIToken)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("missing loader status = %d, want %d", response.Code, http.StatusServiceUnavailable)
	}
}

func TestPolicyReloadRequiresConfiguredBearerToken(t *testing.T) {
	network := newPolicyReloadTestNetwork(t)
	network.SetAPIToken("")
	request := httptest.NewRequest(http.MethodPost, "/egress-policy/reload", nil)
	response := httptest.NewRecorder()
	network.ServicesMux().ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status without configured token = %d, want %d", response.Code, http.StatusUnauthorized)
	}
}
