# 2FA

Система двухфакторной аутентификации на Go с API и RADIUS.

## Старт
```bash
go test ./...
```
```bash
go run ./cmd/migrate
```

## Структура
- `cmd/api-server` — API сервер
- `cmd/radius-server` — RADIUS сервер
- `internal` — бизнес-логика и сервисы
- `pkg` — общие библиотеки

## Сервисные эндпоинты
- `GET /healthz` — healthcheck
- `GET /metrics` — метрики (заглушка)

## Auth API
- `POST /api/v1/auth/login` — логин + создание challenge
- `POST /api/v1/auth/verify` — подтверждение 2FA
- `POST /api/v1/auth/refresh` — обновление токена
- `POST /api/v1/auth/logout` — выход
  - login возвращает `status` и время жизни challenge
- `GET /api/v1/sessions` — список сессий пользователя
- `GET /api/v1/sessions/current` — текущая сессия
- `POST /api/v1/sessions/revoke` — отзыв сессии
- `POST /api/v1/sessions/revoke_all` — отзыв всех сессий
- `GET /api/v1/lockouts/current` — текущая блокировка

## UI
- `GET /ui/` — минимальный web‑интерфейс для auth/2FA и сессий

## OpenAPI
- `docs/openapi.yaml`
## Observability
- `docs/observability/slo_sli.md`
- `docs/observability/alerts.yaml`
## Security
- `docs/security.md`
## Production
- `docs/production.md`

## Конфигурация
- env: `configs/config.example.env`
- файл: `configs/config.example.yaml` (используется при `CONFIG_PATH`)
- обязательные параметры: `DB_URL`, `JWT_SECRET`, `ADMIN_JWT_SECRET`, `RADIUS_SECRET`
- провайдеры 2FA: `EXPRESS_MOBILE_URL`, `EXPRESS_MOBILE_KEY`, `FCM_SERVER_KEY`
- TTL: `AUTH_CHALLENGE_TTL`, `SESSION_TTL`
- JWT: `JWT_SECRET`, `JWT_ISSUER`, `JWT_TTL`
- rate limit: `REDIS_URL`, `AUTH_LOGIN_LIMIT`, `AUTH_VERIFY_LIMIT`

## Админ‑API CRUD
- пользователи: `/api/v1/admin/users/*`
- политики: `/api/v1/admin/policies/*`
- RADIUS клиенты: `/api/v1/admin/radius/clients/*`
- роли и права: `/api/v1/admin/role-permissions*`
- группы: `/api/v1/admin/groups*`
- сессии: `/api/v1/admin/sessions` (фильтры `user_id`, `active_only`, `ip`, `user_agent`)

## Валидация
- email, телефон (E.164), IP проверяются на входе
