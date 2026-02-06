## Релиз: аудит 2FA verify

### Изменения
- Аудит подтверждения 2FA: `second_factor_approve` и `second_factor_deny`.
- Добавлен `AuditEntityChallenge`.
- Обновлена документация по безопасности.

### Тестирование
- `go test ./...` — успешно.
