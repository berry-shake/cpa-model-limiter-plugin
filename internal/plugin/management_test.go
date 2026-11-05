package plugin

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

func pluginapiRequest(key, model string) pluginapi.FrontendAuthRequest {
	return pluginapi.FrontendAuthRequest{
		Path:    "/v1/chat/completions",
		Headers: http.Header{"Authorization": {"Bearer " + key}},
		Body:    []byte(`{"model":"` + model + `"}`),
	}
}

func TestStateEndpointReturnsHostKeysAndRules(t *testing.T) {
	t.Parallel()
	service := New("0.1.3", nil, fakeHostKeys("sk-alpha", "sk-beta"))
	service.Call("plugin.register", registerPayload(t, `
keys:
  - api-key: sk-alpha
    models: [gpt-5.2]
`))

	resp := service.handleManagement(managementRPCRequest{Method: http.MethodGet, Path: statePath})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d body = %s", resp.StatusCode, resp.Body)
	}
	var body stateResponse
	if errDecode := json.Unmarshal(resp.Body, &body); errDecode != nil {
		t.Fatal(errDecode)
	}
	if body.PluginVersion != "0.1.3" {
		t.Fatalf("plugin_version = %q", body.PluginVersion)
	}
	if len(body.APIKeys) != 2 || body.APIKeys[0] != "sk-alpha" || body.APIKeys[1] != "sk-beta" {
		t.Fatalf("api_keys sorted = %+v", body.APIKeys)
	}
	if len(body.Rules) != 1 || body.Rules[0].APIKey != "sk-alpha" || len(body.Rules[0].Models) != 1 || body.Rules[0].Models[0] != "gpt-5.2" {
		t.Fatalf("rules = %+v", body.Rules)
	}
}

func TestApplyEndpointWritesAndReflectsUpdatedState(t *testing.T) {
	t.Parallel()
	service := New("0.1.3", nil, fakeHostKeys("sk-alpha", "sk-beta"))
	path := newTempConfig(t, "api-keys:\n  - sk-alpha\n  - sk-beta\n")
	service.writer = newConfigWriter(func() string { return path })

	payload := []jsonRule{
		{APIKey: "sk-beta", Models: []string{"claude-*"}},
		{APIKey: "sk-alpha", Models: []string{"gpt-5.2"}},
	}
	raw, errMarshal := json.Marshal(applyRequest{Rules: &payload})
	if errMarshal != nil {
		t.Fatal(errMarshal)
	}

	resp := service.handleManagement(managementRPCRequest{
		Method: http.MethodPost,
		Path:   applyPath,
		Body:   raw,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d body = %s", resp.StatusCode, resp.Body)
	}

	var body stateResponse
	if errDecode := json.Unmarshal(resp.Body, &body); errDecode != nil {
		t.Fatal(errDecode)
	}
	if len(body.Rules) != 2 {
		t.Fatalf("rules = %+v", body.Rules)
	}
	if body.Rules[0].APIKey != "sk-alpha" || body.Rules[1].APIKey != "sk-beta" {
		t.Fatalf("rules must be sorted; got %+v", body.Rules)
	}

	rules := service.Rules()
	if len(rules) != 2 || rules[0].APIKey != "sk-alpha" || rules[1].APIKey != "sk-beta" {
		t.Fatalf("in-memory rules not updated: %+v", rules)
	}

	authResp := service.Authenticate(pluginapiRequest("sk-alpha", "claude-3.5"))
	if authResp.Authenticated {
		t.Fatal("sk-alpha should be restricted to gpt-5.2 after apply")
	}
	authResp = service.Authenticate(pluginapiRequest("sk-alpha", "gpt-5.2"))
	if !authResp.Authenticated {
		t.Fatal("sk-alpha should still allow gpt-5.2 after apply")
	}
}

func TestApplyEndpointClearsRulesOnEmptyPayload(t *testing.T) {
	t.Parallel()
	service := New("0.1.3", nil, fakeHostKeys("sk-alpha"))
	path := newTempConfig(t, sampleConfig)
	service.writer = newConfigWriter(func() string { return path })
	service.Call("plugin.register", registerPayload(t, `
keys:
  - api-key: sk-alpha
    models: [gpt-5.2]
`))

	resp := service.handleManagement(managementRPCRequest{
		Method: http.MethodPost,
		Path:   applyPath,
		Body:   []byte(`{"rules":[]}`),
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d body = %s", resp.StatusCode, resp.Body)
	}
	if len(service.Rules()) != 0 {
		t.Fatalf("rules should be empty after apply []; got %+v", service.Rules())
	}
	authResp := service.Authenticate(pluginapiRequest("sk-alpha", "claude-3.5"))
	if !authResp.Authenticated {
		t.Fatal("sk-alpha should be unrestricted once rules are cleared")
	}
}

func TestApplyEndpointRejectsBadPayload(t *testing.T) {
	t.Parallel()
	service := New("0.1.3", nil, fakeHostKeys("sk-alpha"))
	service.writer = newConfigWriter(func() string { return newTempConfig(t, sampleConfig) })

	post := func(body string) pluginapi.ManagementResponse {
		return service.handleManagement(managementRPCRequest{Method: http.MethodPost, Path: applyPath, Body: []byte(body)})
	}
	if missing := post(`{}`); missing.StatusCode != http.StatusBadRequest || !strings.Contains(string(missing.Body), "missing_rules") {
		t.Fatalf("missing rules response = %d %s", missing.StatusCode, missing.Body)
	}
	if empty := post(""); empty.StatusCode != http.StatusBadRequest || !strings.Contains(string(empty.Body), "invalid_rules") {
		t.Fatalf("empty body response = %d %s", empty.StatusCode, empty.Body)
	}
	if badJSON := post("not json"); badJSON.StatusCode != http.StatusBadRequest || !strings.Contains(string(badJSON.Body), "invalid_rules") {
		t.Fatalf("bad json response = %d %s", badJSON.StatusCode, badJSON.Body)
	}
	if notArray := post(`{"rules":{"api_key":"sk-a"}}`); notArray.StatusCode != http.StatusBadRequest {
		t.Fatalf("non-array rules response = %d %s", notArray.StatusCode, notArray.Body)
	}
	if duplicate := post(`{"rules":[{"api_key":"sk-a"},{"api_key":"sk-a"}]}`); duplicate.StatusCode != http.StatusBadRequest || !strings.Contains(string(duplicate.Body), "apply_failed") {
		t.Fatalf("duplicate api-key response = %d %s", duplicate.StatusCode, duplicate.Body)
	}
}

// A GET must never mutate rules, so a stray navigation cannot rewrite config.yaml.
func TestApplyEndpointRejectsGet(t *testing.T) {
	t.Parallel()
	service := New("0.1.3", nil, fakeHostKeys("sk-alpha"))
	resp := service.handleManagement(managementRPCRequest{
		Method: http.MethodGet,
		Path:   applyPath,
		Query:  map[string][]string{"rules": {"W10"}},
	})
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}

func TestStateEndpointRejectsPost(t *testing.T) {
	t.Parallel()
	service := New("0.1.3", nil, fakeHostKeys("sk-alpha"))
	resp := service.handleManagement(managementRPCRequest{Method: http.MethodPost, Path: statePath})
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}

func TestPanelResponseAppliesFrameAncestors(t *testing.T) {
	t.Parallel()

	service := New("0.1.3", nil, fakeHostKeys())
	resp := service.handleManagement(managementRPCRequest{Method: http.MethodGet, Path: panelPath})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	csp := resp.Headers.Get("Content-Security-Policy")
	if !strings.HasSuffix(csp, "frame-ancestors 'self'") {
		t.Fatalf("empty allowed_origins must allow only the same-origin panel; csp = %q", csp)
	}

	service.Call("plugin.register", registerPayload(t, "allowed_origins: 'https://ops.example.com , https://ops.example.com/'\n"))
	resp = service.handleManagement(managementRPCRequest{Method: http.MethodGet, Path: panelPath})
	csp = resp.Headers.Get("Content-Security-Policy")
	if !strings.Contains(csp, "frame-ancestors 'self' https://ops.example.com") {
		t.Fatalf("allowed_origins must widen frame-ancestors; csp = %q", csp)
	}
	if strings.Count(csp, "https://ops.example.com") != 1 {
		t.Fatalf("duplicate origin should be collapsed; csp = %q", csp)
	}
}

// The panel page must call the authenticated Management API routes and send
// the management key; the old unauthenticated resource endpoints are gone.
func TestPanelPageUsesManagementRoutes(t *testing.T) {
	t.Parallel()
	page := string(panelPage)
	for _, want := range []string{statePath, applyPath, "Authorization", "'Bearer '", "cli-proxy-auth"} {
		if !strings.Contains(page, want) {
			t.Fatalf("panel page should reference %q", want)
		}
	}
	for _, stale := range []string{"/v0/resource/plugins/model-limiter/state", "/v0/resource/plugins/model-limiter/apply", "?rules="} {
		if strings.Contains(page, stale) {
			t.Fatalf("panel page still references %q", stale)
		}
	}
}
