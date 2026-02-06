## Релиз: lockout метрики, CSV экспорт и фильтры сессий

### Изменения
- Метрики lockout: created/active/cleared.
- CSV экспорт audit событий.
- Фильтр `active_only` для админских сессий.
- Обновления OpenAPI и документации observability.

### Тестирование
- `go test ./...` — успешно.
