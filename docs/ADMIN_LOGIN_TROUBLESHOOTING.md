# Устранение проблемы admin_login_failed

## Проблема

При попытке входа в админку возникает ошибка 401:
```json
{
  "status": 401,
  "payload": {
    "error": "admin_login_failed"
  }
}
```

## Проверка данных администратора

### 1. Проверка существования администратора

```powershell
$postgresPod = kubectl get pods -l app=postgres -o jsonpath='{.items[0].metadata.name}'
kubectl exec $postgresPod -- psql -U user -d 2fa -c "SELECT username, status, role FROM users WHERE role = 'admin';"
```

Должно быть:
- `username = 'admin'`
- `status = 'active'`
- `role = 'admin'`

### 2. Проверка хеша пароля

```sql
SELECT 
    username,
    LENGTH(password_hash) as hash_length,
    LEFT(password_hash, 7) as hash_start,
    password_hash IS NOT NULL as hash_not_null
FROM users 
WHERE username = 'admin';
```

Должно быть:
- `hash_length = 60`
- `hash_start = '$2a$10$'`
- `hash_not_null = true`

### 3. Исправление хеша пароля

Если хеш неправильный, выполните:

```powershell
.\scripts\fix-admin-password.ps1
```

Или вручную через SQL:

```sql
-- Хеш для пароля "admin123"
UPDATE users 
SET password_hash = '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy',
    updated_at = now()
WHERE username = 'admin' AND role = 'admin';
```

## Проверка port-forward

Убедитесь, что port-forward работает:

```powershell
# Проверка порта
netstat -ano | Select-String -Pattern ":8083"

# Перезапуск port-forward
$apiPod = kubectl get pods -l app=api-server -o jsonpath='{.items[0].metadata.name}'
kubectl port-forward pod/$apiPod 8083:8080
```

## Тестирование входа

### Через API

```powershell
$body = @{
    username = "admin"
    password = "admin123"
} | ConvertTo-Json

$response = Invoke-RestMethod -Uri "http://localhost:8083/api/v1/admin/auth/login" `
    -Method POST `
    -Body $body `
    -ContentType "application/json"

Write-Host "Token: $($response.access_token)"
```

### Через UI

1. Откройте http://localhost:8083/ui/
2. Перейдите в раздел "Admin login"
3. Введите:
   - Username: `admin`
   - Password: `admin123`
4. Нажмите "Admin login"

## Возможные причины ошибки

1. **Неправильный хеш пароля** - хеш сохранен некорректно или пустой
2. **Пользователь не найден** - администратор не создан или имеет неправильную роль
3. **Неверный статус** - статус не равен 'active'
4. **Port-forward не работает** - порт 8083 не доступен
5. **Неправильный пароль** - введен неверный пароль

## Пошаговая диагностика

1. Проверьте существование администратора в базе
2. Проверьте правильность хеша пароля (должно быть 60 символов)
3. Убедитесь, что status = 'active' и role = 'admin'
4. Проверьте работу port-forward
5. Попробуйте перезапустить API сервер: `kubectl delete pod -l app=api-server`
6. Проверьте логи: `kubectl logs -l app=api-server --tail=50`

## Правильные учетные данные

После исправления используйте:

- **Username**: `admin`
- **Password**: `admin123`
- **Email**: `admin@example.com`
- **Role**: `admin`
- **Status**: `active`

## Быстрое исправление

Выполните скрипт:

```powershell
.\scripts\fix-admin-password.ps1
```

Скрипт автоматически:
- Проверит администратора
- Обновит хеш пароля
- Проверит результат
