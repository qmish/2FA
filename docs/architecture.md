## Архитектура

### Слои
- `cmd/*` — точки входа (API и RADIUS)
- `internal/api` — HTTP handlers/middlewares/router
- `internal/auth` — сервис 2FA и JWT
- `internal/storage/postgres` — репозитории и миграции

### Поток auth
1. `POST /api/v1/auth/login` — проверка первого фактора, создание challenge.
2. `POST /api/v1/auth/verify` — проверка OTP/PUSH/Call, выпуск access/refresh.
3. `POST /api/v1/auth/refresh` — rotation refresh token, новый access.
4. `POST /api/v1/auth/logout` — отзыв сессии.
