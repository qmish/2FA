# Архитектура

## Навигация
- Потоки (auth/passkey/radius): `flows.md`
- Модель данных и хранилища: `data-flows.md`
- Сетевая связанность: `network.md`
- Протоколы и форматы: `protocols.md`
- Интеграции: `integrations.md`

## Слои
- `cmd/*` — точки входа (API и RADIUS)
- `internal/api` — HTTP handlers/middlewares/router
- `internal/auth` — сервис 2FA и JWT
- `internal/storage/postgres` — репозитории и миграции
