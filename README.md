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

## Сервисные эндпоинты
- `GET /healthz` — healthcheck
- `GET /metrics` — метрики (заглушка)

## OpenAPI
- `docs/openapi.yaml`

## Конфигурация
- env: `configs/config.example.env`
- файл: `configs/config.example.yaml` (используется при `CONFIG_PATH`)
- обязательные параметры: `DB_URL`, `ADMIN_JWT_SECRET`, `RADIUS_SECRET`
