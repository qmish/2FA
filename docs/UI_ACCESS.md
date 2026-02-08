# Доступ к UI проекта

## UI встроен в API сервер

UI доступен по пути `/ui/` на API сервере.

## Быстрый запуск

### Вариант 1: Использовать готовый скрипт

```powershell
.\scripts\start-ui.ps1
```

Скрипт автоматически:
- Проверит статус подов
- Найдет работающий API сервер
- Настроит port-forward
- Покажет адреса для доступа

### Вариант 2: Ручная настройка

```powershell
# Получить имя пода
$podName = kubectl get pods -l app=api-server -o jsonpath='{.items[0].metadata.name}'

# Запустить port-forward
kubectl port-forward pod/$podName 8083:8080
```

Затем откройте в браузере: **http://localhost:8083/ui/**

## Доступные адреса

После настройки port-forward доступны:

- **UI**: http://localhost:8083/ui/
- **Health Check**: http://localhost:8083/healthz
- **Metrics**: http://localhost:8083/metrics
- **API**: http://localhost:8083/api/v1/

## Постоянный доступ без port-forward

### Через NodePort

Service `api-server` использует `NodePort` (по умолчанию `30080`):

- **UI**: http://localhost:30080/ui/
- **Health Check**: http://localhost:30080/healthz

Если порт занят, измените `nodePort` в `docs/k8s/api-service.yaml`
и примените манифест.

### Доступ по доменному имени (для локального теста)

1. Добавьте в hosts:
   - **Windows**:
     ```powershell
     Add-Content -Path "C:\Windows\System32\drivers\etc\hosts" -Value "`n127.0.0.1`t2fa.local"
     ```
   - **Linux/macOS**:
     ```bash
     echo "127.0.0.1    2fa.local" | sudo tee -a /etc/hosts
     ```
2. Откройте: http://2fa.local/ui/

Для автоматической настройки используйте:
```powershell
.\scripts\setup-domain.ps1
```

## Доступ к API без port-forward

### Через NodePort
- **Health Check**: http://localhost:30080/healthz
- **Metrics**: http://localhost:30080/metrics
- **API**: http://localhost:30080/api/v1/

### Через port-forward к Service
```powershell
kubectl port-forward svc/api-server 8084:80
```
Затем: http://localhost:8084/healthz

## Возможности UI

UI включает следующие разделы:

1. **Аутентификация**
   - Логин пользователя
   - Логин через passkey (WebAuthn)
   - Подтверждение 2FA
   - Обновление токена
   - Выход

2. **Сессии**
   - Список сессий
   - Текущая сессия
   - Отзыв сессий

3. **Блокировки**
   - Текущая блокировка

4. **Административные функции**
   - Админ логин
   - Просмотр сессий
   - Просмотр блокировок
   - Очистка блокировок
   - Аудит событий
   - Экспорт аудита в CSV

5. **Мониторинг**
   - Health check
   - Метрики Prometheus

## Port-forward к другим сервисам

### RADIUS Server

```powershell
$radiusPod = kubectl get pods -l app=radius-server -o jsonpath='{.items[0].metadata.name}'
kubectl port-forward pod/$radiusPod 1812:1812
```

### PostgreSQL (для отладки)

```powershell
kubectl port-forward pod/postgres-0 5432:5432
```

### Redis (для отладки)

```powershell
kubectl port-forward pod/redis-6d977785bf-7r6cz 6379:6379
```

## Использование скрипта port-forward.ps1

Для запуска port-forward ко всем сервисам:

```powershell
.\scripts\port-forward.ps1
```

## Устранение проблем

### Порт занят

Если порт 8083 занят, используйте другой:

```powershell
kubectl port-forward pod/$podName 8085:8080
```

### Под не запущен

Проверьте статус:

```powershell
kubectl get pods -l app=api-server
```

Если под не запущен:

```powershell
kubectl logs -l app=api-server
kubectl describe pod <имя-пода>
```

### UI не загружается

1. Проверьте, что port-forward работает:
   ```powershell
   curl http://localhost:8083/healthz
   ```

2. Проверьте логи:
   ```powershell
   kubectl logs -l app=api-server --tail=50
   ```

3. Попробуйте прямой доступ к поду:
   ```powershell
   kubectl exec <pod-name> -- wget -qO- http://localhost:8080/ui/
   ```

## Для production

Для production рекомендуется:

1. Настроить Ingress с TLS
2. Использовать LoadBalancer или NodePort
3. Настроить внешний DNS
4. Для passkeys требуется HTTPS и корректный домен (`webauthn_rp_id`, `webauthn_rp_origin`)

Пример Ingress для UI:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: ui-ingress
spec:
  rules:
  - host: ui.example.com
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
