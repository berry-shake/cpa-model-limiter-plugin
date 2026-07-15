package plugin

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
)

// ExtractAPIKey pulls the inbound credential from the same sources the host
// builtin config-api-key provider checks: Authorization bearer, the Google and
// Anthropic key headers, and the key/auth_token query parameters.
func ExtractAPIKey(headers http.Header, query url.Values) string {
	if token := bearerToken(headers.Get("Authorization")); token != "" {
		return token
	}
	if key := strings.TrimSpace(headers.Get("X-Goog-Api-Key")); key != "" {
		return key
	}
	if key := strings.TrimSpace(headers.Get("X-Api-Key")); key != "" {
		return key
	}
	if query != nil {
		if key := strings.TrimSpace(query.Get("key")); key != "" {
			return key
		}
		if key := strings.TrimSpace(query.Get("auth_token")); key != "" {
			return key
		}
	}
	return ""
}

func bearerToken(header string) string {
	header = strings.TrimSpace(header)
	if header == "" {
		return ""
	}
	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 {
		return header
	}
	if !strings.EqualFold(parts[0], "bearer") {
		return header
	}
	return strings.TrimSpace(parts[1])
}

// ExtractModel resolves the requested model from the URL path (Gemini-style
// /models/<model>:<action> routes) or the JSON body "model" field
// (OpenAI/Claude/Codex-style routes). Thinking suffixes such as "(high)" or
// "(8192)" are stripped so allow lists match the plain model name.
func ExtractModel(path string, body []byte) string {
	if model := modelFromPath(path); model != "" {
		return StripThinkingSuffix(model)
	}
	if model := modelFromBody(body); model != "" {
		return StripThinkingSuffix(model)
	}
	return ""
}

func modelFromPath(path string) string {
	const marker = "/models/"
	position := strings.LastIndex(path, marker)
	if position < 0 {
		return ""
	}
	rest := path[position+len(marker):]
	if colon := strings.IndexByte(rest, ':'); colon >= 0 {
		rest = rest[:colon]
	}
	if slash := strings.IndexByte(rest, '/'); slash >= 0 {
		rest = rest[:slash]
	}
	if unescaped, errUnescape := url.PathUnescape(rest); errUnescape == nil {
		rest = unescaped
	}
	return strings.TrimSpace(rest)
}

func modelFromBody(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	var payload struct {
		Model string `json:"model"`
	}
	if errUnmarshal := json.Unmarshal(body, &payload); errUnmarshal != nil {
		return ""
	}
	return strings.TrimSpace(payload.Model)
}

// StripThinkingSuffix removes a trailing "(value)" thinking suffix, mirroring
// the host suffix syntax model-name(value).
func StripThinkingSuffix(model string) string {
	if !strings.HasSuffix(model, ")") {
		return model
	}
	open := strings.LastIndex(model, "(")
	if open <= 0 {
		return model
	}
	return model[:open]
}
