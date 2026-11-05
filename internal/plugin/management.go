package plugin

import (
	"encoding/json"
	"net/http"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

const (
	statePath = "/v0/management/plugins/model-limiter/state"
	applyPath = "/v0/management/plugins/model-limiter/apply"
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

// applyRequest is the POST /apply body. Rules is a pointer so a missing field
// is rejected instead of silently clearing every rule.
type applyRequest struct {
	Rules *[]jsonRule `json:"rules"`
}

// handleManagement serves both route families. The panel page and logo are
// unauthenticated GET resources that carry no data. /state and /apply are
// Management API routes: CPA checks the management key before forwarding
// them, so the plugin needs no origin or CSRF checks of its own.
func (s *Service) handleManagement(req managementRPCRequest) pluginapi.ManagementResponse {
	switch req.Path {
	case logoPath:
		if req.Method == http.MethodGet {
			return logoResponse()
		}
	case panelPath:
		if req.Method == http.MethodGet {
			return panelResponse(s.AllowedOrigins())
		}
	case statePath:
		if req.Method == http.MethodGet {
			return s.stateResponse()
		}
	case applyPath:
		if req.Method == http.MethodPost {
			return s.applyResponse(req.Body)
		}
	default:
		return jsonResponse(http.StatusNotFound, errorBody{Error: "not_found", Message: "plugin route not found"})
	}
	return jsonResponse(http.StatusMethodNotAllowed, errorBody{Error: "method_not_allowed", Message: "method not allowed on this route"})
}

func (s *Service) stateResponse() pluginapi.ManagementResponse {
	body, errBuild := s.currentState()
	if errBuild != nil {
		return jsonResponse(http.StatusInternalServerError, errorBody{Error: "state_failed", Message: errBuild.Error()})
	}
	return jsonResponse(http.StatusOK, body)
}

func (s *Service) applyResponse(body []byte) pluginapi.ManagementResponse {
	var req applyRequest
	if errJSON := json.Unmarshal(body, &req); errJSON != nil {
		return jsonResponse(http.StatusBadRequest, errorBody{Error: "invalid_rules", Message: "request body must be JSON {\"rules\": [...]}: " + errJSON.Error()})
	}
	if req.Rules == nil {
		return jsonResponse(http.StatusBadRequest, errorBody{Error: "missing_rules", Message: "rules field is required; send [] to clear every rule"})
	}
	rules := make([]RuleEntry, 0, len(*req.Rules))
	for _, entry := range *req.Rules {
		rules = append(rules, RuleEntry{APIKey: entry.APIKey, Models: entry.Models})
	}
	if _, errApply := s.ApplyRules(rules); errApply != nil {
		return jsonResponse(http.StatusBadRequest, errorBody{Error: "apply_failed", Message: errApply.Error()})
	}
	state, errBuild := s.currentState()
	if errBuild != nil {
		return jsonResponse(http.StatusInternalServerError, errorBody{Error: "state_failed", Message: errBuild.Error()})
	}
	return jsonResponse(http.StatusOK, state)
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
