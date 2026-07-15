package plugin

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

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

func TestRegisterReportsExclusiveCapability(t *testing.T) {
	t.Parallel()

	service := New("1.0.0", nil)
	var registration rpcRegistration
	decodeEnvelope(t, service.Call(pluginabi.MethodPluginRegister, registerPayload(t, "enabled: true\n")), &registration)
	if !registration.Capabilities.FrontendAuthProvider {
		t.Fatal("frontend auth capability missing")
	}
	if registration.Capabilities.FrontendAuthProviderExclusive {
		t.Fatal("exclusive should default to false")
	}

	decodeEnvelope(t, service.Call(pluginabi.MethodPluginReconfigure, registerPayload(t, "enabled: true\nexclusive: true\n")), &registration)
	if !registration.Capabilities.FrontendAuthProviderExclusive {
		t.Fatal("exclusive should follow config")
	}
}

func TestFrontendAuthIdentifier(t *testing.T) {
	t.Parallel()

	service := New("1.0.0", nil)
	var identifier rpcIdentifierResponse
	decodeEnvelope(t, service.Call(pluginabi.MethodFrontendAuthIdentifier, nil), &identifier)
	if identifier.Identifier != ProviderID {
		t.Fatalf("identifier = %q", identifier.Identifier)
	}
}

func TestAuthenticateEnforcesModelAllowList(t *testing.T) {
	t.Parallel()

	service := New("1.0.0", nil)
	service.Call(pluginabi.MethodPluginRegister, registerPayload(t, `
enabled: true
keys:
  - api-key: sk-alpha
    models:
      - gpt-5.2
      - claude-*
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
			// Unlisted keys are not handled: the host access manager falls
			// through to the builtin api-keys provider.
			name: "unknown key falls through",
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

func TestAuthenticateViaRPCMethod(t *testing.T) {
	t.Parallel()

	service := New("1.0.0", nil)
	service.Call(pluginabi.MethodPluginRegister, registerPayload(t, `
enabled: true
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

	service := New("1.0.0", nil)
	service.Call(pluginabi.MethodPluginRegister, registerPayload(t, "keys:\n  - api-key: sk-alpha\n"))
	// A rejected reconfigure (duplicate keys) must reset to empty rules
	// rather than keeping stale rules silently: sk-alpha falls back to the
	// host api-keys provider, where a restricted key is not listed.
	service.Call(pluginabi.MethodPluginReconfigure, registerPayload(t, "keys: [{api-key: a}, {api-key: a}]\n"))

	resp := service.Authenticate(pluginapi.FrontendAuthRequest{
		Path:    "/v1/chat/completions",
		Headers: http.Header{"Authorization": {"Bearer sk-alpha"}},
		Body:    []byte(`{"model":"gpt-5.2"}`),
	})
	if resp.Authenticated {
		t.Fatal("stale rules should not survive a failed reconfigure")
	}
}
