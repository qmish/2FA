# Наблюдаемость

## Логирование
- структурные JSON‑логи через `pkg/logger`
- обязательный `X-Request-ID` для корреляции
- уровни: info/warn/error (можно расширить)

## Метрики
- `GET /metrics` — базовые счётчики (http/auth)
- SLO/SLI: `docs/observability/slo_sli.md`
- Alerts: `docs/observability/alerts.yaml`
- Lockout метрики: `lockout_created_total`, `lockout_active_total`, `lockout_cleared_total`
- Регистрация: `auth_registrations_total{result="success|failed"}`
- Логины: `auth_logins_total{result="success|failed"}`
- Passkey: `passkey_events_total{operation="register_begin|register_finish|login_begin|login_finish",result="success|failed"}`
- Очистка WebAuthn-сессий: `webauthn_sessions_cleared_total`

## Tracing
- Включается через `OTEL_EXPORTER_OTLP_ENDPOINT` (например, `http://otel-collector:4318`).
- Имя сервиса: `OTEL_SERVICE_NAME` (по умолчанию `2fa`).
- Семплинг: `OTEL_SAMPLE_RATIO` (0..1).

## ServiceMonitor
- Пример для Prometheus Operator: `docs/k8s/api-servicemonitor.yaml`.

## Логирование
- Базовый стек Loki/Promtail: `docs/k8s/logging-loki.yaml`, `docs/k8s/logging-promtail.yaml`.

## Alertmanager
- Базовый пример развёртывания: `docs/k8s/alertmanager.yaml`.

## Ретенция
- Политика ретенции и примеры настроек: `docs/observability/retention.md`.

## Grafana
- Импорт дашборда: `docs/observability/grafana-import.md`.

## Доступ
- Политика доступа: `docs/observability/access-policy.md`.

## Healthcheck
- `GET /healthz` — проверка доступности сервиса, БД и Redis
