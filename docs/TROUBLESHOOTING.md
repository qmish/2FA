# Устранение проблемы 404

## Проблема
При обращении к API через Service получается ошибка "404 page not found".

## Решение

### 1. Проверка работы приложения внутри пода
Приложение работает корректно внутри пода:
```bash
kubectl exec api-server-6674f97c9b-w6dlt -- wget -qO- http://localhost:8080/healthz
# Результат: ok
```

### 2. Правильный доступ через port-forward

**Вариант 1: Port-forward к Service (рекомендуется)**
```powershell
kubectl port-forward svc/api-server 8080:80
```
Затем откройте: http://localhost:8080/healthz

**Вариант 2: Port-forward напрямую к поду**
```powershell
kubectl port-forward pod/api-server-6674f97c9b-w6dlt 8080:8080
```
Затем откройте: http://localhost:8080/healthz

### 3. Доступные эндпоинты

**Публичные (без аутентификации):**
- `GET /healthz` - Health check
- `GET /metrics` - Метрики
- `POST /api/v1/auth/login` - Логин
- `POST /api/v1/auth/verify` - Подтверждение 2FA
- `POST /api/v1/auth/refresh` - Обновление токена
- `GET /ui/` - Web интерфейс

**Требуют аутентификации:**
- `POST /api/v1/auth/logout` - Выход
- `GET /api/v1/sessions` - Список сессий
- `GET /api/v1/sessions/current` - Текущая сессия
- И другие...

**Административные (требуют admin токен):**
- `POST /api/v1/admin/auth/login` - Админ логин
- `GET /api/v1/admin/users` - Список пользователей
- И другие...

### 4. Проверка конфигурации Service

Service настроен правильно:
- Порт: 80 (внешний)
- Target Port: 8080 (внутренний порт контейнера)
- Тип: ClusterIP (доступен только внутри кластера)

### 5. Для доступа извне кластера

**Вариант A: Использовать LoadBalancer (если настроен)**
```yaml
spec:
  type: LoadBalancer
```

**Вариант B: Использовать Ingress**
Создайте Ingress ресурс для внешнего доступа.

**Вариант C: Port-forward (для разработки)**
```powershell
kubectl port-forward svc/api-server 8080:80
```

## Тестирование

```powershell
# Health check
Invoke-WebRequest -Uri http://localhost:8080/healthz

# Метрики
Invoke-WebRequest -Uri http://localhost:8080/metrics

# Логин (пример)
$body = @{
    username = "test"
    password = "test"
} | ConvertTo-Json
Invoke-WebRequest -Uri http://localhost:8080/api/v1/auth/login -Method POST -Body $body -ContentType "application/json"
```

## Примечания

- Service использует порт 80 для внешнего доступа, но маппит на порт 8080 контейнера
- При использовании `kubectl port-forward` убедитесь, что указаны правильные порты
- Для production рекомендуется настроить Ingress с TLS
