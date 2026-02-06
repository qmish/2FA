## Релиз: SLI метрики и системные ошибки

### Изменения
- Добавлены histogram метрики latency (`http_request_duration_ms`).
- Счетчик системных ошибок (`system_errors_total`) для DB/Redis.
- Интеграция метрик в middleware и healthcheck.
- Обновлены SLO/SLI и алерты.

### Тестирование
- `go test ./...` — успешно.
