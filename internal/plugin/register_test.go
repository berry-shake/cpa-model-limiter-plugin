package plugin

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

func fakeHostKeys(keys ...string) HostKeysResolver {
	ordered := append([]string(nil), keys...)
	set := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		set[key] = struct{}{}
	}
	snapshot := HostKeysSnapshot{Ordered: ordered, Set: set}
	return func() (HostKeysSnapshot, error) {
		return snapshot, nil
	}
}

func registerPayload(t *testing.T, configYAML string) []byte {
	t.Helper()
	raw, errMarshal := json.Marshal(rpcLifecycleRequest{ConfigYAML: []byte(configYAML)})
	if errMarshal != nil {
		t.Fatal(errMarshal)
	}
	return raw
}

func decodeEnvelope(t *testing.T, raw []byte, out any) {
	t.Helper()
	var envelope pluginabi.Envelope
	if errUnmarshal := json.Unmarshal(raw, &envelope); errUnmarshal != nil {
		t.Fatal(errUnmarshal)
	}
	if !envelope.OK {
		t.Fatalf("envelope not ok: %+v", envelope.Error)
	}
	if out != nil {
		if errUnmarshal := json.Unmarshal(envelope.Result, out); errUnmarshal != nil {
			t.Fatal(errUnmarshal)
		}
	}
}

func TestRegisterReportsExclusiveCapabilities(t *testing.T) {
	t.Parallel()

	service := New("1.0.0", nil, fakeHostKeys())
	var registration rpcRegistration
	decodeEnvelope(t, service.Call(pluginabi.MethodPluginRegister, registerPayload(t, "keys: []\n")), &registration)
	if !registration.Capabilities.FrontendAuthProvider {
		t.Fatal("frontend auth capability missing")
	}
	if !registration.Capabilities.FrontendAuthProviderExclusive {
		t.Fatal("exclusive capability must always be reported")
	}
	if !registration.Capabilities.ManagementAPI {
		t.Fatal("management api capability missing")
	}
}

func TestFrontendAuthIdentifier(t *testing.T) {
	t.Parallel()

	service := New("1.0.0", nil, fakeHostKeys())
	var identifier rpcIdentifierResponse
	decodeEnvelope(t, service.Call(pluginabi.MethodFrontendAuthIdentifier, nil), &identifier)
	if identifier.Identifier != ProviderID {
		t.Fatalf("identifier = %q", identifier.Identifier)
	}
}

func TestAuthenticateRequiresHostKeyAndAllowedModel(t *testing.T) {
	t.Parallel()

	service := New("1.0.0", nil, fakeHostKeys("sk-alpha", "sk-open"))
	service.Call(pluginabi.MethodPluginRegister, registerPayload(t, `
keys:
  - api-key: sk-alpha
    models:
      - gpt-5.2
      - claude-*
  - api-key: sk-ghost
    models:
      - gpt-5.2
`))

	tests := []struct {
		name string
		req  pluginapi.FrontendAuthRequest
		want bool
	}{
		{
			name: "allowed model",
			req: pluginapi.FrontendAuthRequest{
				Path:    "/v1/chat/completions",
				Headers: http.Header{"Authorization": {"Bearer sk-alpha"}},
				Body:    []byte(`{"model":"gpt-5.2"}`),
			},
			want: true,
		},
		{
			name: "allowed with thinking suffix",
			req: pluginapi.FrontendAuthRequest{
				Path:    "/v1/messages",
				Headers: http.Header{"X-Api-Key": {"sk-alpha"}},
				Body:    []byte(`{"model":"claude-sonnet-4-5(16384)"}`),
			},
			want: true,
		},
		{
			name: "denied model",
			req: pluginapi.FrontendAuthRequest{
				Path:    "/v1/chat/completions",
				Headers: http.Header{"Authorization": {"Bearer sk-alpha"}},
				Body:    []byte(`{"model":"gemini-2.5-pro"}`),
			},
			want: false,
		},
		{
			// A key that only exists in the plugin rules but not in the host
			// api-keys list must be rejected: rules never grant access.
			name: "rule-only key rejected",
			req: pluginapi.FrontendAuthRequest{
				Path:    "/v1/chat/completions",
				Headers: http.Header{"Authorization": {"Bearer sk-ghost"}},
				Body:    []byte(`{"model":"gpt-5.2"}`),
			},
			want: false,
		},
		{
			name: "unknown key rejected",
			req: pluginapi.FrontendAuthRequest{
				Path:    "/v1/chat/completions",
				Headers: http.Header{"Authorization": {"Bearer sk-unknown"}},
				Body:    []byte(`{"model":"gpt-5.2"}`),
			},
			want: false,
		},
		{
			name: "missing key",
			req: pluginapi.FrontendAuthRequest{
				Path:    "/v1/chat/completions",
				Headers: http.Header{},
				Body:    []byte(`{"model":"gpt-5.2"}`),
			},
			want: false,
		},
		{
			// A host key without a plugin rule is unrestricted.
			name: "host key without rule passes",
			req: pluginapi.FrontendAuthRequest{
				Path:    "/v1/chat/completions",
				Headers: http.Header{"Authorization": {"Bearer sk-open"}},
				Body:    []byte(`{"model":"gemini-2.5-pro"}`),
			},
			want: true,
		},
		{
			name: "model-less endpoint passes key check",
			req: pluginapi.FrontendAuthRequest{
				Path:    "/v1/models",
				Headers: http.Header{"Authorization": {"Bearer sk-alpha"}},
			},
			want: true,
		},
		{
			name: "gemini path model denied",
			req: pluginapi.FrontendAuthRequest{
				Path:    "/v1beta/models/gemini-2.5-pro:generateContent",
				Headers: http.Header{"X-Goog-Api-Key": {"sk-alpha"}},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			resp := service.Authenticate(tt.req)
			if resp.Authenticated != tt.want {
				t.Fatalf("Authenticated = %v, want %v", resp.Authenticated, tt.want)
			}
			if tt.want && resp.Principal == "" {
				t.Fatal("principal should be set on success")
			}
		})
	}
}

func TestAuthenticateFailsClosedWhenHostKeysUnavailable(t *testing.T) {
	t.Parallel()

	failing := func() (HostKeysSnapshot, error) {
		return HostKeysSnapshot{}, errors.New("boom")
	}
	service := New("1.0.0", nil, failing)
	resp := service.Authenticate(pluginapi.FrontendAuthRequest{
		Path:    "/v1/chat/completions",
		Headers: http.Header{"Authorization": {"Bearer sk-alpha"}},
		Body:    []byte(`{"model":"gpt-5.2"}`),
	})
	if resp.Authenticated {
		t.Fatal("must reject when the host api-keys list cannot be read")
	}
}

func TestAuthenticateViaRPCMethod(t *testing.T) {
	t.Parallel()

	service := New("1.0.0", nil, fakeHostKeys("sk-alpha"))
	service.Call(pluginabi.MethodPluginRegister, registerPayload(t, `
keys:
  - api-key: sk-alpha
    models: [gpt-5.2]
`))

	raw, errMarshal := json.Marshal(pluginapi.FrontendAuthRequest{
		Path:    "/v1/chat/completions",
		Headers: http.Header{"Authorization": {"Bearer sk-alpha"}},
		Body:    []byte(`{"model":"gpt-5.2"}`),
	})
	if errMarshal != nil {
		t.Fatal(errMarshal)
	}
	var resp pluginapi.FrontendAuthResponse
	decodeEnvelope(t, service.Call(pluginabi.MethodFrontendAuthAuthenticate, raw), &resp)
	if !resp.Authenticated {
		t.Fatal("expected authenticated response")
	}
}

func TestBrokenConfigResetsToEmptyRules(t *testing.T) {
	t.Parallel()

	service := New("1.0.0", nil, fakeHostKeys("sk-alpha"))
	service.Call(pluginabi.MethodPluginRegister, registerPayload(t, `
keys:
  - api-key: sk-alpha
    models: [gpt-5.2]
`))
	// A rejected reconfigure (duplicate keys) resets to empty rules: keys in
	// the host api-keys list become unrestricted rather than being locked out
	// by stale rules.
	service.Call(pluginabi.MethodPluginReconfigure, registerPayload(t, "keys: [{api-key: a}, {api-key: a}]\n"))

	resp := service.Authenticate(pluginapi.FrontendAuthRequest{
		Path:    "/v1/chat/completions",
		Headers: http.Header{"Authorization": {"Bearer sk-alpha"}},
		Body:    []byte(`{"model":"gemini-2.5-pro"}`),
	})
	if !resp.Authenticated {
		t.Fatal("host key should be unrestricted after rules reset")
	}
}

func TestManagementRegisterExposesPanelResource(t *testing.T) {
	t.Parallel()

	service := New("1.0.0", nil, fakeHostKeys())
	var registration managementRegistration
	decodeEnvelope(t, service.Call(pluginabi.MethodManagementRegister, nil), &registration)
	paths := map[string]resourceDeclaration{}
	for _, res := range registration.Resources {
		paths[res.Path] = res
	}
	panel, okPanel := paths["/panel"]
	if !okPanel || panel.Menu == "" {
		t.Fatalf("panel resource must be a menu entry, got %+v", panel)
	}
	for _, sub := range []string{"/state", "/apply"} {
		res, ok := paths[sub]
		if !ok {
			t.Fatalf("missing resource %q, got %+v", sub, registration.Resources)
		}
		if res.Menu != "" {
			t.Fatalf("%q must not surface as a menu entry, got %+v", sub, res)
		}
	}
}

func TestManagementHandleServesPanelPage(t *testing.T) {
	t.Parallel()

	service := New("1.0.0", nil, fakeHostKeys())
	raw, errMarshal := json.Marshal(managementRPCRequest{Method: http.MethodGet, Path: panelPath})
	if errMarshal != nil {
		t.Fatal(errMarshal)
	}
	var resp pluginapi.ManagementResponse
	decodeEnvelope(t, service.Call(pluginabi.MethodManagementHandle, raw), &resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if got := resp.Headers.Get("Content-Type"); !strings.HasPrefix(got, "text/html") {
		t.Fatalf("content type = %q", got)
	}
	if !strings.Contains(string(resp.Body), "Model Limiter") {
		t.Fatal("panel body should mention Model Limiter")
	}
}

func TestManagementHandleRejectsNonGetAndUnknownPath(t *testing.T) {
	t.Parallel()

	service := New("1.0.0", nil, fakeHostKeys())

	post := service.handleManagement(managementRPCRequest{Method: http.MethodPost, Path: panelPath})
	if post.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("post status = %d", post.StatusCode)
	}
	missing := service.handleManagement(managementRPCRequest{Method: http.MethodGet, Path: "/v0/resource/plugins/model-limiter/nope"})
	if missing.StatusCode != http.StatusNotFound {
		t.Fatalf("missing status = %d", missing.StatusCode)
	}
}
