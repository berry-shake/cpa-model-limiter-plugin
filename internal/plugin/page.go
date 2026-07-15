package plugin

import (
	_ "embed"
	"net/http"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

//go:embed page.html
var panelPage []byte

func panelResponse(allowedOrigins []string) pluginapi.ManagementResponse {
	return pluginapi.ManagementResponse{
		StatusCode: http.StatusOK,
		Headers: http.Header{
			"Content-Type":            []string{"text/html; charset=utf-8"},
			"Cache-Control":           []string{"no-store"},
			"X-Content-Type-Options":  []string{"nosniff"},
			"Content-Security-Policy": []string{buildCSP(allowedOrigins)},
		},
		Body: append([]byte(nil), panelPage...),
	}
}

func buildCSP(allowedOrigins []string) string {
	frameAncestors := "'none'"
	if len(allowedOrigins) > 0 {
		frameAncestors = "'self' " + strings.Join(allowedOrigins, " ")
	}
	return strings.Join([]string{
		"default-src 'none'",
		"style-src 'unsafe-inline'",
		"script-src 'unsafe-inline'",
		"img-src 'self' data:",
		"connect-src 'self'",
		"base-uri 'none'",
		"form-action 'none'",
		"frame-ancestors " + frameAncestors,
	}, "; ")
}
