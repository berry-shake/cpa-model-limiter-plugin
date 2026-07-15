package plugin

import (
	_ "embed"
	"net/http"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

const logoPath = "/v0/resource/plugins/model-limiter/logo.png"

//go:embed logo.png
var logoPNG []byte

func logoResponse() pluginapi.ManagementResponse {
	return pluginapi.ManagementResponse{
		StatusCode: http.StatusOK,
		Headers: http.Header{
			"Content-Type":  []string{"image/png"},
			"Cache-Control": []string{"no-store"},
		},
		Body: logoPNG,
	}
}
