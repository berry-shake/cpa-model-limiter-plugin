package plugin

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

const (
	statePath = "/v0/resource/plugins/model-limiter/state"
	applyPath = "/v0/resource/plugins/model-limiter/apply"
)

type errorBody struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

// jsonRule is the wire shape for a rule in /state and /apply payloads.
type jsonRule struct {
	APIKey string   `json:"api_key"`
	Models []string `json:"models,omitempty"`
}

type stateResponse struct {
	PluginVersion string     `json:"plugin_version"`
	APIKeys       []string   `json:"api_keys"`
	Rules         []jsonRule `json:"rules"`
}

// handleManagement serves the plugin resource routes. The host restricts
// resource routes to GET only, so mutations use a base64url-encoded query
// payload instead of a request body.
//
// SECURITY: /state and /apply are unauthenticated at the host layer. Cross-
// origin browser requests are rejected here unless the origin is listed in
// allowed_origins, and the panel HTML denies iframe embedding by default via
// frame-ancestors 'none'.
func (s *Service) handleManagement(req managementRPCRequest) pluginapi.ManagementResponse {
	if req.Method != http.MethodGet {
		return jsonResponse(http.StatusMethodNotAllowed, errorBody{Error: "method_not_allowed", Message: "only GET is accepted on resource routes"})
	}
	if req.Path == logoPath {
		return logoResponse()
	}
	origins := s.AllowedOrigins()
	switch req.Path {
	case panelPath:
		return panelResponse(origins)
	case statePath:
		if resp, ok := s.enforceOrigin(req, origins); !ok {
			return resp
		}
		return s.stateResponse()
	case applyPath:
		if resp, ok := s.enforceOrigin(req, origins); !ok {
			return resp
		}
		return s.applyResponse(req)
	default:
		return jsonResponse(http.StatusNotFound, errorBody{Error: "not_found", Message: "plugin route not found"})
	}
}

// enforceOrigin rejects cross-origin browser requests on the state/apply
// endpoints. Cross-origin is always rejected unless the declared origin
// (Origin header, falling back to Referer) matches allowed_origins, so the
// empty default is the strictest setting. Same-origin browser requests and
// requests without any browser context headers (CLI tools) are permitted.
//
// Detection is layered: Sec-Fetch-Site is authoritative when present (the
// browser forbids pages from forging Sec- headers). Without it, a bare
// Origin header implies a cross-origin fetch because browsers omit Origin
// on same-origin GET requests. A Referer alone is ambiguous on legacy
// browsers, so it only causes rejection once allowed_origins is configured.
func (s *Service) enforceOrigin(req managementRPCRequest, allowed []string) (pluginapi.ManagementResponse, bool) {
	headers := req.Headers
	site := strings.ToLower(strings.TrimSpace(headers.Get("Sec-Fetch-Site")))
	if site == "same-origin" || site == "none" {
		return pluginapi.ManagementResponse{}, true
	}
	origin := requestOrigin(headers)
	if origin != "" {
		for _, candidate := range allowed {
			if strings.EqualFold(candidate, origin) {
				return pluginapi.ManagementResponse{}, true
			}
		}
	}
	crossOrigin := site == "same-site" || site == "cross-site" ||
		strings.TrimSpace(headers.Get("Origin")) != "" ||
		(origin != "" && len(allowed) > 0)
	if crossOrigin {
		return jsonResponse(http.StatusForbidden, errorBody{
			Error:   "origin_not_allowed",
			Message: "cross-origin requests are rejected; add trusted origins to allowed_origins",
		}), false
	}
	return pluginapi.ManagementResponse{}, true
}

func requestOrigin(headers http.Header) string {
	if headers == nil {
		return ""
	}
	if raw := strings.TrimSpace(headers.Get("Origin")); raw != "" && raw != "null" {
		return strings.TrimRight(raw, "/")
	}
	referer := strings.TrimSpace(headers.Get("Referer"))
	if referer == "" {
		return ""
	}
	parsed, errParse := url.Parse(referer)
	if errParse != nil || parsed.Scheme == "" || parsed.Host == "" {
		return ""
	}
	return strings.TrimRight(parsed.Scheme+"://"+parsed.Host, "/")
}

func (s *Service) stateResponse() pluginapi.ManagementResponse {
	body, errBuild := s.currentState()
	if errBuild != nil {
		return jsonResponse(http.StatusInternalServerError, errorBody{Error: "state_failed", Message: errBuild.Error()})
	}
	return jsonResponse(http.StatusOK, body)
}

func (s *Service) applyResponse(req managementRPCRequest) pluginapi.ManagementResponse {
	values, ok := req.Query["rules"]
	if !ok || len(values) == 0 {
		return jsonResponse(http.StatusBadRequest, errorBody{Error: "missing_rules", Message: "rules query parameter is required (base64url-encoded JSON array)"})
	}
	rules, errDecode := decodeRulesQuery(values[0])
	if errDecode != nil {
		return jsonResponse(http.StatusBadRequest, errorBody{Error: "invalid_rules", Message: errDecode.Error()})
	}
	if _, errApply := s.ApplyRules(rules); errApply != nil {
		return jsonResponse(http.StatusBadRequest, errorBody{Error: "apply_failed", Message: errApply.Error()})
	}
	body, errBuild := s.currentState()
	if errBuild != nil {
		return jsonResponse(http.StatusInternalServerError, errorBody{Error: "state_failed", Message: errBuild.Error()})
	}
	return jsonResponse(http.StatusOK, body)
}

func (s *Service) currentState() (stateResponse, error) {
	snap, errKeys := s.hostKeys()
	if errKeys != nil {
		return stateResponse{}, errKeys
	}
	list := append([]string(nil), snap.Ordered...)
	rules := s.Rules()
	wire := make([]jsonRule, 0, len(rules))
	for _, rule := range rules {
		wire = append(wire, jsonRule{APIKey: rule.APIKey, Models: rule.Models})
	}
	return stateResponse{
		PluginVersion: s.version,
		APIKeys:       list,
		Rules:         wire,
	}, nil
}

func decodeRulesQuery(encoded string) ([]RuleEntry, error) {
	if encoded == "" {
		return nil, errors.New("rules query parameter is empty")
	}
	raw, errDecode := base64.RawURLEncoding.DecodeString(encoded)
	if errDecode != nil {
		// Accept padded base64url too, so hand-crafted URLs still work.
		raw, errDecode = base64.URLEncoding.DecodeString(encoded)
		if errDecode != nil {
			return nil, errors.New("rules must be base64url-encoded JSON: " + errDecode.Error())
		}
	}
	var parsed []jsonRule
	if errJSON := json.Unmarshal(raw, &parsed); errJSON != nil {
		return nil, errors.New("rules payload is not a JSON array: " + errJSON.Error())
	}
	out := make([]RuleEntry, 0, len(parsed))
	for _, entry := range parsed {
		out = append(out, RuleEntry{APIKey: entry.APIKey, Models: entry.Models})
	}
	return out, nil
}

func jsonResponse(statusCode int, value any) pluginapi.ManagementResponse {
	raw, errMarshal := json.Marshal(value)
	if errMarshal != nil {
		statusCode = http.StatusInternalServerError
		raw = []byte(`{"error":"marshal_failed","message":"failed to encode response"}`)
	}
	return pluginapi.ManagementResponse{
		StatusCode: statusCode,
		Headers: http.Header{
			"Content-Type":  []string{"application/json; charset=utf-8"},
			"Cache-Control": []string{"no-store"},
		},
		Body: raw,
	}
}
