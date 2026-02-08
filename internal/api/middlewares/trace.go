package middlewares

import (
	"net/http"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

func Trace(next http.Handler) http.Handler {
	return otelhttp.NewHandler(next, "http_request")
}
