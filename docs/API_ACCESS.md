# Доступ к API

## Проблема: 404 page not found

Если вы получаете ошибку "404 page not found" при обращении к `http://localhost:8080/healthz`, это означает, что порт 8080 занят другим процессом (не нашим API сервером).

## Решение

### Вариант 1: Port-forward к поду (рекомендуется)

Используйте свободный порт:

```powershell
# Получить имя пода
$podName = kubectl get pods -l app=api-server -o jsonpath='{.items[0].metadata.name}'

# Port-forward на свободный порт (например, 8083)
kubectl port-forward pod/$podName 8083:8080
```

Затем откройте в браузере: **http://localhost:8083/healthz**

### Вариант 2: Port-forward к Service

```powershell
kubectl port-forward svc/api-server 8084:80
```

Затем откройте: **http://localhost:8084/healthz**

### Вариант 3: Проверка внутри кластера

```powershell
# Проверка через exec
kubectl exec api-server-6674f97c9b-w6dlt -- wget -qO- http://localhost:8080/healthz
# Результат: ok
```

## Доступные эндпоинты

### Публичные (без аутентификации)

- `GET /healthz` - Health check
- `GET /metrics` - Метрики Prometheus
- `POST /api/v1/auth/login` - Логин пользователя
- `POST /api/v1/auth/verify` - Подтверждение 2FA
- `POST /api/v1/auth/refresh` - Обновление токена
- `GET /ui/` - Web интерфейс

### Требуют аутентификации (JWT токен)

- `POST /api/v1/auth/logout` - Выход
- `GET /api/v1/sessions` - Список сессий пользователя
- `GET /api/v1/sessions/current` - Текущая сессия
- `POST /api/v1/sessions/revoke` - Отзыв сессии
- `POST /api/v1/sessions/revoke_all` - Отзыв всех сессий
- `GET /api/v1/lockouts/current` - Текущая блокировка

### Административные (требуют admin токен)

- `POST /api/v1/admin/auth/login` - Админ логин
- `GET /api/v1/admin/users` - Список пользователей
- `POST /api/v1/admin/users/create` - Создание пользователя
- И другие...

## Примеры использования

### Health Check

```powershell
# Через port-forward на порт 8083
Invoke-WebRequest -Uri http://localhost:8083/healthz
```

### Логин

```powershell
$body = @{
    username = "testuser"
    password = "testpass"
} | ConvertTo-Json

Invoke-RestMethod -Uri http://localhost:8083/api/v1/auth/login `
    -Method POST `
    -Body $body `
    -ContentType "application/json"
```

### Проверка метрик

```powershell
Invoke-WebRequest -Uri http://localhost:8083/metrics
```

## Проверка статуса

```powershell
# Статус подов
kubectl get pods -l app=api-server

# Логи API сервера
kubectl logs -l app=api-server --tail=50

# Проверка Service
kubectl get svc api-server
```

## Для production

Для production рекомендуется:

1. Настроить Ingress с TLS
2. Использовать LoadBalancer или NodePort
3. Настроить внешний DNS

Пример Ingress:
```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: api-ingress
spec:
  rules:
  - host: api.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: api-server
            port:
              number: 80
```

## Устранение проблем

Если port-forward не работает:

1. Проверьте, что под запущен:
   ```powershell
   kubectl get pods -l app=api-server
   ```

2. Проверьте логи:
   ```powershell
   kubectl logs -l app=api-server
   ```

3. Используйте другой порт для port-forward

4. Проверьте, не занят ли порт:
   ```powershell
   netstat -ano | Select-String -Pattern ":8080"
   ```
