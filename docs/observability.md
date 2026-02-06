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

## Healthcheck
- `GET /healthz` — проверка доступности сервиса, БД и Redis
