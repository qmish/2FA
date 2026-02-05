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

## Админ‑API CRUD
- пользователи: `/api/v1/admin/users/*`
- политики: `/api/v1/admin/policies/*`
- RADIUS клиенты: `/api/v1/admin/radius/clients/*`
- роли и права: `/api/v1/admin/role-permissions*`
- группы: `/api/v1/admin/groups*`

## Валидация
- email, телефон (E.164), IP проверяются на входе
