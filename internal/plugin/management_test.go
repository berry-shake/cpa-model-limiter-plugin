package plugin

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
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
	raw, errMarshal := json.Marshal(payload)
	if errMarshal != nil {
		t.Fatal(errMarshal)
	}
	encoded := base64.RawURLEncoding.EncodeToString(raw)

	resp := service.handleManagement(managementRPCRequest{
		Method: http.MethodGet,
		Path:   applyPath,
		Query:  map[string][]string{"rules": {encoded}},
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

	encoded := base64.RawURLEncoding.EncodeToString([]byte("[]"))
	resp := service.handleManagement(managementRPCRequest{
		Method: http.MethodGet,
		Path:   applyPath,
		Query:  map[string][]string{"rules": {encoded}},
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

	missing := service.handleManagement(managementRPCRequest{Method: http.MethodGet, Path: applyPath})
	if missing.StatusCode != http.StatusBadRequest || !strings.Contains(string(missing.Body), "missing_rules") {
		t.Fatalf("missing rules response = %d %s", missing.StatusCode, missing.Body)
	}
	badBase64 := service.handleManagement(managementRPCRequest{
		Method: http.MethodGet,
		Path:   applyPath,
		Query:  map[string][]string{"rules": {"%%not-base64%%"}},
	})
	if badBase64.StatusCode != http.StatusBadRequest || !strings.Contains(string(badBase64.Body), "invalid_rules") {
		t.Fatalf("bad base64 response = %d %s", badBase64.StatusCode, badBase64.Body)
	}
	badJSON := service.handleManagement(managementRPCRequest{
		Method: http.MethodGet,
		Path:   applyPath,
		Query:  map[string][]string{"rules": {base64.RawURLEncoding.EncodeToString([]byte("not json"))}},
	})
	if badJSON.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad json response = %d", badJSON.StatusCode)
	}
	duplicate := service.handleManagement(managementRPCRequest{
		Method: http.MethodGet,
		Path:   applyPath,
		Query:  map[string][]string{"rules": {base64.RawURLEncoding.EncodeToString([]byte(`[{"api_key":"sk-a"},{"api_key":"sk-a"}]`))}},
	})
	if duplicate.StatusCode != http.StatusBadRequest || !strings.Contains(string(duplicate.Body), "apply_failed") {
		t.Fatalf("duplicate api-key response = %d %s", duplicate.StatusCode, duplicate.Body)
	}
}

func TestApplyEndpointRejectsPost(t *testing.T) {
	t.Parallel()
	service := New("0.1.3", nil, fakeHostKeys("sk-alpha"))
	resp := service.handleManagement(managementRPCRequest{Method: http.MethodPost, Path: applyPath})
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
	if !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Fatalf("empty allowed_origins must forbid iframe embedding; csp = %q", csp)
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

func TestStateEndpointRejectsCrossOriginByDefault(t *testing.T) {
	t.Parallel()

	service := New("0.1.3", nil, fakeHostKeys("sk-alpha"))

	// A CLI request with no browser context headers is allowed.
	bare := service.handleManagement(managementRPCRequest{Method: http.MethodGet, Path: statePath})
	if bare.StatusCode != http.StatusOK {
		t.Fatalf("bare CLI request should pass; status = %d body = %s", bare.StatusCode, bare.Body)
	}

	// A same-origin GET from the panel page is allowed via Sec-Fetch-Site.
	sameOrigin := service.handleManagement(managementRPCRequest{
		Method:  http.MethodGet,
		Path:    statePath,
		Headers: http.Header{"Sec-Fetch-Site": {"same-origin"}},
	})
	if sameOrigin.StatusCode != http.StatusOK {
		t.Fatalf("same-origin request should pass; status = %d", sameOrigin.StatusCode)
	}

	// A cross-origin fetch is rejected regardless of what Origin claims.
	crossOrigin := service.handleManagement(managementRPCRequest{
		Method:  http.MethodGet,
		Path:    statePath,
		Headers: http.Header{"Origin": {"https://attacker.example"}},
	})
	if crossOrigin.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-origin request must be forbidden; status = %d body = %s", crossOrigin.StatusCode, crossOrigin.Body)
	}
	if !strings.Contains(string(crossOrigin.Body), "origin_not_allowed") {
		t.Fatalf("response should identify origin rejection; body = %s", crossOrigin.Body)
	}

	// Referer-only cross-origin without allowed_origins is treated as ambiguous
	// (CLI or legacy browser) and passes.
	refererOnly := service.handleManagement(managementRPCRequest{
		Method:  http.MethodGet,
		Path:    statePath,
		Headers: http.Header{"Referer": {"https://ops.example.com/panel"}},
	})
	if refererOnly.StatusCode != http.StatusOK {
		t.Fatalf("referer-only without allowed_origins should pass; status = %d", refererOnly.StatusCode)
	}
}

func TestStateEndpointAcceptsListedOrigin(t *testing.T) {
	t.Parallel()

	service := New("0.1.3", nil, fakeHostKeys("sk-alpha"))
	service.Call("plugin.register", registerPayload(t, "allowed_origins: 'https://ops.example.com'\n"))

	allowed := service.handleManagement(managementRPCRequest{
		Method:  http.MethodGet,
		Path:    statePath,
		Headers: http.Header{"Origin": {"https://ops.example.com"}},
	})
	if allowed.StatusCode != http.StatusOK {
		t.Fatalf("listed origin must pass; status = %d body = %s", allowed.StatusCode, allowed.Body)
	}

	// Once allowed_origins is set, an unlisted Referer becomes a positive
	// cross-origin signal and is rejected.
	rejected := service.handleManagement(managementRPCRequest{
		Method:  http.MethodGet,
		Path:    statePath,
		Headers: http.Header{"Referer": {"https://attacker.example/x"}},
	})
	if rejected.StatusCode != http.StatusForbidden {
		t.Fatalf("unlisted referer with allowed_origins configured must be rejected; status = %d", rejected.StatusCode)
	}
}
