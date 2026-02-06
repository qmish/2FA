# Решение проблемы admin_login_failed

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

## ✅ Проверено

- ✅ Хеш пароля в базе данных правильный (60 символов)
- ✅ Статус пользователя = 'active'
- ✅ Роль = 'admin'
- ✅ Пользователь существует в базе

## Решение

### Шаг 1: Перезапуск API сервера

API сервер может кэшировать данные или не перечитать из базы. Перезапустите:

```powershell
kubectl delete pod -l app=api-server
```

Подождите 15-20 секунд пока поды перезапустятся.

### Шаг 2: Запуск port-forward

**В отдельном терминале PowerShell:**

```powershell
$apiPod = kubectl get pods -l app=api-server -o jsonpath='{.items[0].metadata.name}'
kubectl port-forward pod/$apiPod 8083:8080
```

**Оставьте этот терминал открытым!**

### Шаг 3: Вход в админку

1. Откройте UI: http://localhost:8083/ui/
2. Перейдите в раздел "Admin login"
3. Введите:
   - Username: `admin`
   - Password: `admin123`
4. Нажмите "Admin login"

### Шаг 4: Если все еще не работает

Проверьте хеш пароля еще раз:

```powershell
$postgresPod = kubectl get pods -l app=postgres -o jsonpath='{.items[0].metadata.name}'
kubectl exec $postgresPod -- psql -U user -d 2fa -c "SELECT username, LENGTH(password_hash) as len, LEFT(password_hash, 10) as start FROM users WHERE username = 'admin';"
```

Должно быть:
- `len = 60`
- `start = '$2a$10$N9'`

Если хеш неправильный, исправьте:

```powershell
Get-Content scripts/fix-admin-hash.sql | kubectl exec -i $postgresPod -- psql -U user -d 2fa
```

Затем снова перезапустите API сервер.

## Учетные данные

- **Username**: `admin`
- **Password**: `admin123`

## Альтернативный способ проверки

Проверьте вход напрямую через API:

```powershell
$body = @{
    username = "admin"
    password = "admin123"
} | ConvertTo-Json

try {
    $response = Invoke-RestMethod -Uri "http://localhost:8083/api/v1/admin/auth/login" `
        -Method POST `
        -Body $body `
        -ContentType "application/json"
    
    Write-Host "✅ Вход успешен!"
    Write-Host "Token: $($response.access_token)"
} catch {
    Write-Host "❌ Ошибка: $($_.Exception.Message)"
    if ($_.Exception.Response) {
        $stream = $_.Exception.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($stream)
        $responseBody = $reader.ReadToEnd()
        Write-Host "Ответ: $responseBody"
    }
}
```

## Диагностика

Если проблема сохраняется после перезапуска:

1. **Проверьте логи API:**
```powershell
kubectl logs -l app=api-server --tail=50 | Select-String -Pattern "admin|login"
```

2. **Проверьте данные в базе:**
```sql
SELECT username, status, role, LENGTH(password_hash) as len 
FROM users 
WHERE username = 'admin' AND role = 'admin';
```

3. **Пересоздайте администратора:**
```powershell
.\scripts\fix-admin-password.ps1
```

## Важно

⚠️ После исправления хеша пароля **обязательно перезапустите API сервер**, иначе изменения не применятся!
