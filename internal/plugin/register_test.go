package plugin

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
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

// zstdLike stands in for a compressed body: bytes the plugin cannot parse.
var zstdLike = []byte{0x28, 0xb5, 0x2f, 0xfd, 0x04, 0x00, 0x51, 0x00}

func restrictedService(t *testing.T) *Service {
	t.Helper()
	service := New("1.0.0", nil, fakeHostKeys("sk-alpha", "sk-open"))
	service.Call(pluginabi.MethodPluginRegister, registerPayload(t, `
keys:
  - api-key: sk-alpha
    models: [gpt-5.2]
`))
	return service
}

func TestAuthenticateDenyStatus(t *testing.T) {
	t.Parallel()

	service := restrictedService(t)
	denied := service.Authenticate(pluginapi.FrontendAuthRequest{
		Path:    "/v1/chat/completions",
		Headers: http.Header{"Authorization": {"Bearer sk-alpha"}},
		Body:    []byte(`{"model":"gemini-2.5-pro"}`),
	})
	if denied.Authenticated || denied.DenyStatusCode != http.StatusForbidden {
		t.Fatalf("denied model = %+v, want 403", denied)
	}
	if !strings.Contains(denied.DenyMessage, "gemini-2.5-pro") {
		t.Fatalf("deny message should name the model, got %q", denied.DenyMessage)
	}

	// Unknown keys stay unhandled so the host answers with its own 401.
	unknown := service.Authenticate(pluginapi.FrontendAuthRequest{
		Path:    "/v1/chat/completions",
		Headers: http.Header{"Authorization": {"Bearer sk-unknown"}},
		Body:    []byte(`{"model":"gpt-5.2"}`),
	})
	if unknown.Authenticated || unknown.DenyStatusCode != 0 || unknown.DenyMessage != "" {
		t.Fatalf("unknown key = %+v, want empty response", unknown)
	}
}

func TestAuthenticateEncodedBodies(t *testing.T) {
	t.Parallel()

	service := restrictedService(t)
	zstd := http.Header{"Content-Encoding": {"zstd"}}
	tests := []struct {
		name       string
		key        string
		headers    http.Header
		body       []byte
		decoded    []byte
		want       bool
		wantStatus int
		wantModel  string
	}{
		{name: "decoded allowed model", key: "sk-alpha", headers: zstd, body: zstdLike, decoded: []byte(`{"model":"gpt-5.2"}`), want: true, wantModel: "gpt-5.2"},
		{name: "decoded denied model", key: "sk-alpha", headers: zstd, body: zstdLike, decoded: []byte(`{"model":"gemini-2.5-pro"}`), wantStatus: http.StatusForbidden},
		{
			// The raw body must not be consulted once a decoded copy exists.
			name: "decoded body wins over raw", key: "sk-alpha", headers: zstd,
			body: []byte(`{"model":"gpt-5.2"}`), decoded: []byte(`{"model":"gemini-2.5-pro"}`), wantStatus: http.StatusForbidden,
		},
		{
			// Older hosts or long coding lists: the handler may still decode
			// what the plugin cannot read, so restricted keys fail closed.
			name: "undecoded body rejected for restricted key", key: "sk-alpha", headers: zstd, body: zstdLike, wantStatus: http.StatusUnsupportedMediaType,
		},
		{
			// A decoy object ahead of the real frame must not be trusted.
			name: "undecoded body with decoy model rejected", key: "sk-alpha", headers: zstd,
			body: append(append([]byte{0x50, 0x2a, 0x4d, 0x18, 19, 0, 0, 0}, `{"model":"gpt-5.2"}`...), zstdLike...), wantStatus: http.StatusUnsupportedMediaType,
		},
		{name: "undecoded body passes for unrestricted key", key: "sk-open", headers: zstd, body: zstdLike, want: true},
		{
			// The handler falls back to a raw body that is valid JSON.
			name: "undecodable JSON body checked as is", key: "sk-alpha", headers: http.Header{"Content-Encoding": {"gzip"}},
			body: []byte(`{"model":"gemini-2.5-pro"}`), wantStatus: http.StatusForbidden,
		},
		{name: "identity encoding is plain", key: "sk-alpha", headers: http.Header{"Content-Encoding": {"identity"}}, body: []byte(`{"model":"gpt-5.2"}`), want: true, wantModel: "gpt-5.2"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			headers := tt.headers.Clone()
			headers.Set("Authorization", "Bearer "+tt.key)
			resp := service.Authenticate(pluginapi.FrontendAuthRequest{
				Method:      http.MethodPost,
				Path:        "/v1/chat/completions",
				Headers:     headers,
				Body:        tt.body,
				DecodedBody: tt.decoded,
			})
			if resp.Authenticated != tt.want || resp.DenyStatusCode != tt.wantStatus {
				t.Fatalf("got authenticated=%v status=%d, want %v/%d", resp.Authenticated, resp.DenyStatusCode, tt.want, tt.wantStatus)
			}
			if tt.want && resp.Metadata["model"] != tt.wantModel {
				t.Fatalf("metadata model = %q, want %q", resp.Metadata["model"], tt.wantModel)
			}
		})
	}
}

func TestAuthenticateDecodedBodyViaRPCMethod(t *testing.T) {
	t.Parallel()

	service := restrictedService(t)
	// The host marshals pluginapi.FrontendAuthRequest as is, so DecodedBody
	// crosses the RPC boundary under its Go field name.
	raw, errMarshal := json.Marshal(pluginapi.FrontendAuthRequest{
		Method:      http.MethodPost,
		Path:        "/v1/chat/completions",
		Headers:     http.Header{"Authorization": {"Bearer sk-alpha"}, "Content-Encoding": {"zstd"}},
		Body:        zstdLike,
		DecodedBody: []byte(`{"model":"gemini-2.5-pro"}`),
	})
	if errMarshal != nil {
		t.Fatal(errMarshal)
	}
	var resp pluginapi.FrontendAuthResponse
	decodeEnvelope(t, service.Call(pluginabi.MethodFrontendAuthAuthenticate, raw), &resp)
	if resp.Authenticated || resp.DenyStatusCode != http.StatusForbidden {
		t.Fatalf("resp = %+v, want 403 deny", resp)
	}
}

func TestRegisterNegotiatesSchemaVersion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		payload []byte
		want    uint32
	}{
		{name: "no payload", payload: nil, want: 1},
		{name: "host without schema", payload: []byte(`{"config_yaml":null}`), want: 1},
		{name: "older host", payload: []byte(`{"schema_version":3}`), want: 3},
		{name: "host at pinned schema", payload: []byte(`{"schema_version":6}`), want: 6},
		{name: "newer host", payload: []byte(`{"schema_version":10,"multi_auth_providers":true}`), want: maxSchemaVersion},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			service := New("1.0.0", nil, fakeHostKeys())
			for _, method := range []string{pluginabi.MethodPluginRegister, pluginabi.MethodPluginReconfigure} {
				var registration rpcRegistration
				decodeEnvelope(t, service.Call(method, tt.payload), &registration)
				if registration.SchemaVersion != tt.want {
					t.Fatalf("%s schema_version = %d, want %d", method, registration.SchemaVersion, tt.want)
				}
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

func TestManagementRegisterSplitsResourcesAndManagementRoutes(t *testing.T) {
	t.Parallel()

	service := New("1.0.0", nil, fakeHostKeys())
	raw := service.Call(pluginabi.MethodManagementRegister, nil)
	var registration managementRegistration
	decodeEnvelope(t, raw, &registration)
	paths := map[string]resourceDeclaration{}
	for _, res := range registration.Resources {
		paths[res.Path] = res
	}
	panel, okPanel := paths["/panel"]
	if !okPanel || panel.Menu == "" {
		t.Fatalf("panel resource must be a menu entry, got %+v", panel)
	}
	if logo, ok := paths["/logo.png"]; !ok || logo.Menu != "" {
		t.Fatalf("logo must be a non-menu resource, got %+v", registration.Resources)
	}
	for _, private := range []string{"/state", "/apply"} {
		if _, ok := paths[private]; ok {
			t.Fatalf("%q must not be an unauthenticated resource", private)
		}
	}

	// Decode with the host's shape: CPA reads routes into pluginapi.ManagementRoute.
	var host struct {
		Routes []pluginapi.ManagementRoute `json:"routes"`
	}
	decodeEnvelope(t, raw, &host)
	got := map[string]string{}
	for _, route := range host.Routes {
		got[route.Method+" "+route.Path] = route.Description
	}
	for _, want := range []string{http.MethodGet + " " + statePath, http.MethodPost + " " + applyPath} {
		if _, ok := got[want]; !ok {
			t.Fatalf("missing management route %q, got %+v", want, host.Routes)
		}
	}
	if len(host.Routes) != 2 {
		t.Fatalf("unexpected management routes: %+v", host.Routes)
	}
}

func TestMetadataAdvertisesLogoResource(t *testing.T) {
	t.Parallel()

	service := New("1.0.0", nil, fakeHostKeys())
	var registration rpcRegistration
	decodeEnvelope(t, service.Call(pluginabi.MethodPluginRegister, nil), &registration)
	if registration.Metadata.Logo != logoPath {
		t.Fatalf("Metadata.Logo = %q, want %q", registration.Metadata.Logo, logoPath)
	}
}

func TestLogoResourceServesEmbeddedPNG(t *testing.T) {
	t.Parallel()

	service := New("1.0.0", nil, fakeHostKeys())
	resp := service.handleManagement(managementRPCRequest{Method: http.MethodGet, Path: logoPath})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if got := resp.Headers.Get("Content-Type"); got != "image/png" {
		t.Fatalf("content-type = %q", got)
	}
	if len(resp.Body) < 8 || string(resp.Body[:8]) != "\x89PNG\r\n\x1a\n" {
		t.Fatalf("body is not a PNG (len=%d)", len(resp.Body))
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

func TestManagementHandleRejectsWrongMethodAndUnknownPath(t *testing.T) {
	t.Parallel()

	service := New("1.0.0", nil, fakeHostKeys())

	post := service.handleManagement(managementRPCRequest{Method: http.MethodPost, Path: panelPath})
	if post.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("post status = %d", post.StatusCode)
	}
	for _, path := range []string{"/v0/resource/plugins/model-limiter/nope", "/v0/resource/plugins/model-limiter/state"} {
		missing := service.handleManagement(managementRPCRequest{Method: http.MethodGet, Path: path})
		if missing.StatusCode != http.StatusNotFound {
			t.Fatalf("%s status = %d", path, missing.StatusCode)
		}
	}
	missing := service.handleManagement(managementRPCRequest{Method: http.MethodGet, Path: "/v0/management/plugins/model-limiter/nope"})
	if missing.StatusCode != http.StatusNotFound {
		t.Fatalf("missing status = %d", missing.StatusCode)
	}
}
