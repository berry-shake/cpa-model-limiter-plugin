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

// buildCSP always allows same-origin framing so the CPA management panel can
// embed the page and share its remembered management key.
func buildCSP(allowedOrigins []string) string {
	frameAncestors := "'self'"
	if len(allowedOrigins) > 0 {
		frameAncestors += " " + strings.Join(allowedOrigins, " ")
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
