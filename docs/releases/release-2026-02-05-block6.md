## Релиз: healthcheck Redis, current session и фильтры

### Изменения
- Healthcheck включает проверку Redis, ошибки учитываются в метриках.
- Новый endpoint `/api/v1/sessions/current`.
- Фильтр `active_only` для пользовательских сессий.
- Обновления OpenAPI и README.

### Тестирование
- `go test ./...` — успешно.
