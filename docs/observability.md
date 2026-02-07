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

## Healthcheck
- `GET /healthz` — проверка доступности сервиса, БД и Redis
