package observability

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/qmish/2FA/internal/config"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
)

func InitTracing(ctx context.Context, cfg config.Config) (func(context.Context) error, error) {
	if strings.TrimSpace(cfg.OTelEndpoint) == "" {
		return func(context.Context) error { return nil }, nil
	}
	endpoint, path, insecure, err := parseOTLPEndpoint(cfg.OTelEndpoint)
	if err != nil {
		return nil, err
	}
	opts := []otlptracehttp.Option{
		otlptracehttp.WithEndpoint(endpoint),
	}
	if path != "" && path != "/" {
		opts = append(opts, otlptracehttp.WithURLPath(path))
	}
	if insecure {
		opts = append(opts, otlptracehttp.WithInsecure())
	}
	exporter, err := otlptracehttp.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceName(cfg.OTelServiceName),
		),
	)
	if err != nil {
		return nil, err
	}
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(cfg.OTelSampleRatio))),
		sdktrace.WithBatcher(exporter),
	)
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.TraceContext{})
	return tp.Shutdown, nil
}

func parseOTLPEndpoint(raw string) (string, string, bool, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", "", false, err
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return "", "", false, fmt.Errorf("invalid otel endpoint: %s", raw)
	}
	insecure := strings.EqualFold(parsed.Scheme, "http")
	return parsed.Host, parsed.Path, insecure, nil
}
