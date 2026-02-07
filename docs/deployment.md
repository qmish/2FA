## Развертывание

### Предварительные требования
- PostgreSQL
- Redis (для rate limit)

### Шаги
1. Настройте `CONFIG_PATH` или переменные окружения по `configs/config.example.yaml`.
   Для passkeys (WebAuthn) обязательно укажите:
   - `webauthn_rp_id` (домен приложения)
   - `webauthn_rp_origin` (https origin)
   - `webauthn_rp_name` (отображаемое имя)
   Passkeys требуют HTTPS и корректный домен.
2. Примените миграции:
   ```bash
   go run ./cmd/migrate
   ```
3. Запустите API:
   ```bash
   go run ./cmd/api-server
   ```
4. Запустите RADIUS (опционально):
   ```bash
   go run ./cmd/radius-server
   ```
