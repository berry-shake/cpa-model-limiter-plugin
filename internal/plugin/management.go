package plugin

import (
	"encoding/json"
	"net/http"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

type errorBody struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

// handleManagement serves the plugin resource routes. The panel page is the
// only route; it edits rules through the host management API directly, so
// no plugin-owned mutation endpoints exist.
func (s *Service) handleManagement(req managementRPCRequest) pluginapi.ManagementResponse {
	if req.Method != http.MethodGet {
		return jsonResponse(http.StatusMethodNotAllowed, errorBody{Error: "method_not_allowed", Message: "only GET is accepted on resource routes"})
	}
	if req.Path == panelPath {
		return panelResponse()
	}
	return jsonResponse(http.StatusNotFound, errorBody{Error: "not_found", Message: "plugin route not found"})
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
