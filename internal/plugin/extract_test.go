package plugin

import (
	"net/http"
	"net/url"
	"testing"
)

func TestExtractAPIKeySources(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		headers http.Header
		query   url.Values
		want    string
	}{
		{
			name:    "authorization bearer",
			headers: http.Header{"Authorization": {"Bearer sk-token"}},
			want:    "sk-token",
		},
		{
			name:    "authorization raw",
			headers: http.Header{"Authorization": {"sk-raw"}},
			want:    "sk-raw",
		},
		{
			name:    "google header",
			headers: http.Header{"X-Goog-Api-Key": {"sk-goog"}},
			want:    "sk-goog",
		},
		{
			name:    "anthropic header",
			headers: http.Header{"X-Api-Key": {"sk-anthropic"}},
			want:    "sk-anthropic",
		},
		{
			name:  "query key",
			query: url.Values{"key": {"sk-query"}},
			want:  "sk-query",
		},
		{
			name:  "query auth token",
			query: url.Values{"auth_token": {"sk-auth"}},
			want:  "sk-auth",
		},
		{
			name: "missing",
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			headers := tt.headers
			if headers == nil {
				headers = http.Header{}
			}
			if got := ExtractAPIKey(headers, tt.query); got != tt.want {
				t.Fatalf("ExtractAPIKey() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestExtractModelFromBody(t *testing.T) {
	t.Parallel()

	model := ExtractModel("/v1/chat/completions", []byte(`{"model":"gpt-5.2(high)","stream":true}`))
	if model != "gpt-5.2" {
		t.Fatalf("model = %q", model)
	}
}

func TestExtractModelFromGeminiPath(t *testing.T) {
	t.Parallel()

	model := ExtractModel("/v1beta/models/gemini-2.5-pro:streamGenerateContent", nil)
	if model != "gemini-2.5-pro" {
		t.Fatalf("model = %q", model)
	}
}

func TestExtractModelPathBeatsBody(t *testing.T) {
	t.Parallel()

	model := ExtractModel("/v1beta/models/gemini-2.5-flash:generateContent", []byte(`{"model":"other"}`))
	if model != "gemini-2.5-flash" {
		t.Fatalf("model = %q", model)
	}
}

func TestExtractModelMissing(t *testing.T) {
	t.Parallel()

	if model := ExtractModel("/v1/models", nil); model != "" {
		t.Fatalf("model = %q, want empty", model)
	}
	if model := ExtractModel("/v1/chat/completions", []byte("not-json")); model != "" {
		t.Fatalf("model = %q, want empty", model)
	}
}

func TestStripThinkingSuffix(t *testing.T) {
	t.Parallel()

	tests := []struct {
		in   string
		want string
	}{
		{"claude-sonnet-4-5(16384)", "claude-sonnet-4-5"},
		{"gpt-5.2(high)", "gpt-5.2"},
		{"gemini-2.5-pro", "gemini-2.5-pro"},
		{"(weird)", "(weird)"},
	}
	for _, tt := range tests {
		if got := StripThinkingSuffix(tt.in); got != tt.want {
			t.Fatalf("StripThinkingSuffix(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
