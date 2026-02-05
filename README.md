# 2FA

Система двухфакторной аутентификации на Go с API и RADIUS.

## Старт
```bash
go test ./...
```

## Структура
- `cmd/api-server` — API сервер
- `cmd/radius-server` — RADIUS сервер
- `internal` — бизнес-логика и сервисы
- `pkg` — общие библиотеки
