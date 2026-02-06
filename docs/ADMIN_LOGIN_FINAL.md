# Финальное решение проблемы admin_login_failed

## ✅ Статус

Хеш пароля исправлен в базе данных (60 символов). Проблема может быть связана с port-forward или кэшированием данных в приложении.

## Учетные данные

- **Username**: `admin`
- **Password**: `admin123`
- **Email**: `admin@example.com`

## Пошаговое решение

### Шаг 1: Проверка данных в базе

```powershell
$postgresPod = kubectl get pods -l app=postgres -o jsonpath='{.items[0].metadata.name}'
kubectl exec $postgresPod -- psql -U user -d 2fa -c "SELECT username, status, role, LENGTH(password_hash) as len FROM users WHERE username = 'admin';"
```

Должно быть:
- `len = 60`
- `status = 'active'`
- `role = 'admin'`

### Шаг 2: Исправление хеша (если нужно)

```powershell
$postgresPod = kubectl get pods -l app=postgres -o jsonpath='{.items[0].metadata.name}'
Get-Content scripts/fix-admin-hash.sql | kubectl exec -i $postgresPod -- psql -U user -d 2fa
```

### Шаг 3: Перезапуск API сервера

```powershell
kubectl delete pod -l app=api-server
```

Подождите 15-20 секунд пока поды перезапустятся.

### Шаг 4: Запуск port-forward

**В отдельном терминале PowerShell выполните:**

```powershell
$apiPod = kubectl get pods -l app=api-server -o jsonpath='{.items[0].metadata.name}'
kubectl port-forward pod/$apiPod 8083:8080
```

**Оставьте этот терминал открытым!**

### Шаг 5: Вход в админку

**В новом терминале:**

```powershell
$body = @{
    username = "admin"
    password = "admin123"
} | ConvertTo-Json

$response = Invoke-RestMethod -Uri "http://localhost:8083/api/v1/admin/auth/login" `
    -Method POST `
    -Body $body `
    -ContentType "application/json"

Write-Host "Access Token: $($response.access_token)"
```

Или через UI:
1. Откройте http://localhost:8083/ui/
2. Раздел "Admin login"
3. Username: `admin`, Password: `admin123`

## Альтернативный способ: Проверка внутри пода

Если port-forward не работает, проверьте напрямую:

```powershell
$apiPod = kubectl get pods -l app=api-server -o jsonpath='{.items[0].metadata.name}'
kubectl exec $apiPod -- sh -c "echo '{\"username\":\"admin\",\"password\":\"admin123\"}' | wget -qO- --post-data=@- --header='Content-Type: application/json' http://localhost:8080/api/v1/admin/auth/login"
```

## Диагностика

Если вход все еще не работает:

1. **Проверьте логи API:**
```powershell
kubectl logs -l app=api-server --tail=50
```

2. **Проверьте, что password_hash не NULL:**
```sql
SELECT password_hash IS NOT NULL, LENGTH(password_hash) 
FROM users WHERE username = 'admin';
```

3. **Проверьте статус пользователя:**
```sql
SELECT username, status, role FROM users WHERE username = 'admin';
```

4. **Пересоздайте администратора через SQL файл:**
```powershell
.\scripts\fix-admin-password.ps1
```

## Важно

⚠️ Убедитесь, что:
- Port-forward запущен в отдельном терминале и не закрыт
- API сервер перезапущен после исправления хеша
- Хеш пароля имеет длину 60 символов
- Статус пользователя = 'active'
- Роль = 'admin'
