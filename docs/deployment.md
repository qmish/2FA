## Развертывание

### Предварительные требования
- PostgreSQL
- Redis (для rate limit)

### Шаги
1. Настройте `CONFIG_PATH` или переменные окружения по `configs/config.example.yaml`.
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
