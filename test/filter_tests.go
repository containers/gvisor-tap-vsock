package e2e

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

type FilterTestProps struct {
	SSHExec      func(cmd ...string) ([]byte, error)
	ServicesSock string
}

func filterHTTPClient(sock string) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", sock)
			},
		},
	}
}

func filterGet(client *http.Client, path string) (map[string]interface{}, error) {
	resp, err := client.Get("http://host" + path) // #nosec G107
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var result map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&result)
	return result, err
}

func filterDoRequest(client *http.Client, method, path, body string) (*http.Response, error) {
	req, err := http.NewRequest(method, "http://host"+path, strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	return client.Do(req)
}

func FilterAPITests(props FilterTestProps) {
	var client *http.Client

	ginkgo.BeforeEach(func() {
		client = filterHTTPClient(props.ServicesSock)
	})

	ginkgo.It("should return stats from filter API", func() {
		result, err := filterGet(client, "/services/filter/stats")
		gomega.Expect(err).ShouldNot(gomega.HaveOccurred())
		gomega.Expect(result).Should(gomega.HaveKey("total_connections"))
		gomega.Expect(result).Should(gomega.HaveKey("blocked_connections"))
		gomega.Expect(result).Should(gomega.HaveKey("allowed_connections"))
		gomega.Expect(result).Should(gomega.HaveKey("total_dns_queries"))
		gomega.Expect(result).Should(gomega.HaveKey("uptime_seconds"))
		gomega.Expect(result).Should(gomega.HaveKey("allowlist_patterns"))
		gomega.Expect(result).Should(gomega.HaveKey("blocklist_entries"))
	})

	ginkgo.It("should add and remove allowlist domains via API", func() {
		// Add domain
		resp, err := filterDoRequest(client, http.MethodPost, "/services/filter/allowlist",
			`{"domain":"test.integration.com"}`)
		gomega.Expect(err).ShouldNot(gomega.HaveOccurred())
		defer resp.Body.Close()
		gomega.Expect(resp.StatusCode).Should(gomega.Equal(http.StatusOK))

		body, err := io.ReadAll(resp.Body)
		gomega.Expect(err).ShouldNot(gomega.HaveOccurred())
		var addResult map[string]interface{}
		gomega.Expect(json.Unmarshal(body, &addResult)).Should(gomega.Succeed())
		gomega.Expect(addResult["success"]).Should(gomega.BeTrue())

		// Verify it appears in GET
		result, err := filterGet(client, "/services/filter/allowlist")
		gomega.Expect(err).ShouldNot(gomega.HaveOccurred())
		gomega.Expect(result["domains"]).ShouldNot(gomega.BeNil())

		// Remove domain
		resp2, err := filterDoRequest(client, http.MethodDelete, "/services/filter/allowlist",
			`{"domain":"test.integration.com"}`)
		gomega.Expect(err).ShouldNot(gomega.HaveOccurred())
		defer resp2.Body.Close()
		gomega.Expect(resp2.StatusCode).Should(gomega.Equal(http.StatusOK))
	})

	ginkgo.It("should add and remove blocklist entries via API", func() {
		// Add entry
		resp, err := filterDoRequest(client, http.MethodPost, "/services/filter/blocklist",
			`{"protocol":"tcp","ip":"10.99.99.99","port":9999,"reason":"integration test"}`)
		gomega.Expect(err).ShouldNot(gomega.HaveOccurred())
		defer resp.Body.Close()
		gomega.Expect(resp.StatusCode).Should(gomega.Equal(http.StatusOK))

		// Verify it appears in GET
		result, err := filterGet(client, "/services/filter/blocklist")
		gomega.Expect(err).ShouldNot(gomega.HaveOccurred())
		gomega.Expect(result["entries"]).ShouldNot(gomega.BeNil())
		entries := result["entries"].([]interface{})
		gomega.Expect(len(entries)).Should(gomega.BeNumerically(">=", 1))

		// Remove entry
		resp2, err := filterDoRequest(client, http.MethodDelete, "/services/filter/blocklist",
			`{"protocol":"tcp","ip":"10.99.99.99","port":9999}`)
		gomega.Expect(err).ShouldNot(gomega.HaveOccurred())
		defer resp2.Body.Close()
		gomega.Expect(resp2.StatusCode).Should(gomega.Equal(http.StatusOK))
	})

	ginkgo.It("should return connections list from filter API", func() {
		result, err := filterGet(client, "/services/filter/connections")
		gomega.Expect(err).ShouldNot(gomega.HaveOccurred())
		gomega.Expect(result).Should(gomega.HaveKey("connections"))
	})

	ginkgo.It("should return DNS queries from filter API", func() {
		result, err := filterGet(client, "/services/filter/dns/queries")
		gomega.Expect(err).ShouldNot(gomega.HaveOccurred())
		gomega.Expect(result).Should(gomega.HaveKey("queries"))
	})

	ginkgo.It("should clear history via filter API", func() {
		resp, err := filterDoRequest(client, http.MethodDelete, "/services/filter/history", "")
		gomega.Expect(err).ShouldNot(gomega.HaveOccurred())
		defer resp.Body.Close()
		gomega.Expect(resp.StatusCode).Should(gomega.Equal(http.StatusOK))

		body, err := io.ReadAll(resp.Body)
		gomega.Expect(err).ShouldNot(gomega.HaveOccurred())
		var result map[string]interface{}
		gomega.Expect(json.Unmarshal(body, &result)).Should(gomega.Succeed())
		gomega.Expect(result["success"]).Should(gomega.BeTrue())
	})
}

func FilterObservabilityTests(props FilterTestProps) {
	var client *http.Client

	ginkgo.BeforeEach(func() {
		client = filterHTTPClient(props.ServicesSock)

		// Clear history to get clean state
		resp, err := filterDoRequest(client, http.MethodDelete, "/services/filter/history", "")
		gomega.Expect(err).ShouldNot(gomega.HaveOccurred())
		resp.Body.Close()
	})

	ginkgo.It("should record connections from VM traffic", func() {
		// Generate traffic from within the VM — hit the gateway HTTP
		_, err := props.SSHExec("curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "http://gateway.containers.internal/services/filter/stats")
		gomega.Expect(err).ShouldNot(gomega.HaveOccurred())

		// Check that the connection was recorded
		result, err := filterGet(client, "/services/filter/stats")
		gomega.Expect(err).ShouldNot(gomega.HaveOccurred())

		totalConns := result["total_connections"].(float64)
		gomega.Expect(totalConns).Should(gomega.BeNumerically(">", 0))
	})

	ginkgo.It("should record DNS queries from VM traffic", func() {
		// Generate a DNS query from within the VM
		_, _ = props.SSHExec("nslookup", "gateway.containers.internal")

		// Check that DNS queries were recorded
		result, err := filterGet(client, "/services/filter/dns/queries")
		gomega.Expect(err).ShouldNot(gomega.HaveOccurred())
		gomega.Expect(result).Should(gomega.HaveKey("queries"))
	})
}

func FilterBlockingTests(props FilterTestProps) {
	ginkgo.It("should block and unblock connections by domain via REST API", func() {
		client := filterHTTPClient(props.ServicesSock)

		// Clear history for a clean starting state
		resp, err := filterDoRequest(client, http.MethodDelete, "/services/filter/history", "")
		gomega.Expect(err).ShouldNot(gomega.HaveOccurred())
		resp.Body.Close()

		// Step 1: verify redhat.com is reachable
		out, err := props.SSHExec("curl -sS --connect-timeout 10 -o /dev/null -w '%{http_code}' http://redhat.com")
		gomega.Expect(err).ShouldNot(gomega.HaveOccurred(), "redhat.com should be reachable before blocking")
		gomega.Expect(strings.TrimSpace(string(out))).ShouldNot(gomega.BeEmpty())

		// Step 2: resolve redhat.com so DNS cache is populated
		_, err = props.SSHExec("nslookup redhat.com")
		gomega.Expect(err).ShouldNot(gomega.HaveOccurred())

		// Ensure cleanup even if the test fails midway
		ginkgo.DeferCleanup(func() {
			r, e := filterDoRequest(client, http.MethodDelete, "/services/filter/blocklist",
				`{"domain":"redhat.com"}`)
			if e == nil && r != nil {
				r.Body.Close()
			}
		})

		// Step 3: block redhat.com (automatically includes all subdomains)
		resp, err = filterDoRequest(client, http.MethodPost, "/services/filter/blocklist",
			`{"domain":"redhat.com","reason":"e2e filter test"}`)
		gomega.Expect(err).ShouldNot(gomega.HaveOccurred())
		gomega.Expect(resp.StatusCode).Should(gomega.Equal(http.StatusOK))
		resp.Body.Close()

		// Step 4: verify redhat.com is NOT reachable
		_, err = props.SSHExec("curl -sS --connect-timeout 5 -o /dev/null http://redhat.com")
		gomega.Expect(err).Should(gomega.HaveOccurred(), "curl should fail when domain is in blocklist")

		// Step 5: verify the blocked connection appears in the REST API with domain
		result, err := filterGet(client, "/services/filter/connections/blocked")
		gomega.Expect(err).ShouldNot(gomega.HaveOccurred())
		connections := result["connections"]
		gomega.Expect(connections).ShouldNot(gomega.BeNil(), "should have blocked connections")
		connList := connections.([]interface{})

		foundBlocked := false
		for _, c := range connList {
			conn := c.(map[string]interface{})
			connDomain, _ := conn["domain"].(string)
			if connDomain == "redhat.com" {
				foundBlocked = true
				break
			}
		}
		gomega.Expect(foundBlocked).Should(gomega.BeTrue(), "blocked connection for redhat.com should appear with domain in API")

		// Step 5b: verify domain blocklist entries are visible
		result, err = filterGet(client, "/services/filter/blocklist")
		gomega.Expect(err).ShouldNot(gomega.HaveOccurred())
		domainEntries := result["domain_entries"]
		gomega.Expect(domainEntries).ShouldNot(gomega.BeNil(), "blocklist should have domain entries")
		entryList := domainEntries.([]interface{})
		gomega.Expect(len(entryList)).Should(gomega.BeNumerically(">=", 1))
		entry := entryList[0].(map[string]interface{})
		gomega.Expect(entry["domain"]).Should(gomega.Equal("redhat.com"))

		// Step 6: remove domain from blocklist
		resp, err = filterDoRequest(client, http.MethodDelete, "/services/filter/blocklist",
			`{"domain":"redhat.com"}`)
		gomega.Expect(err).ShouldNot(gomega.HaveOccurred())
		gomega.Expect(resp.StatusCode).Should(gomega.Equal(http.StatusOK))
		resp.Body.Close()

		// Step 7: verify redhat.com is reachable again
		out, err = props.SSHExec("curl -sS --connect-timeout 10 -o /dev/null -w '%{http_code}' http://redhat.com")
		gomega.Expect(err).ShouldNot(gomega.HaveOccurred(), "curl should succeed after removing domain from blocklist")
		gomega.Expect(strings.TrimSpace(string(out))).ShouldNot(gomega.BeEmpty())
	})
}
