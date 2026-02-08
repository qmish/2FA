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
- RADIUS: `radius_requests_total{result="accept|reject|timeout|error"}`
- Redis: `redis_ping_total{result="success|error"}`
- БД: `db_ping_total{result="success|error"}`
- Пул БД: `db_pool_open_connections`, `db_pool_in_use`, `db_pool_idle`, `db_pool_wait_count`, `db_pool_wait_duration_ms`, `db_pool_max_open_connections`

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
- Примеры SLO/SLA алертов: `docs/observability/alerts.yaml`.

## Ретенция
- Политика ретенции и примеры настроек: `docs/observability/retention.md`.

## Grafana
- Импорт дашборда: `docs/observability/grafana-import.md`.
- Витрина RADIUS: `docs/observability/radius-dashboard.md`.

## Доступ
- Политика доступа: `docs/observability/access-policy.md`.

## Healthcheck
- `GET /healthz` — проверка доступности сервиса, БД и Redis
