# Учетные данные администратора

## ✅ Исправлено!

Хеш пароля был исправлен. Теперь можно войти в админку.

## Учетные данные

- **Username**: `admin`
- **Password**: `admin123`
- **Email**: `admin@example.com`
- **Role**: `admin`
- **Status**: `active`

## Вход в админку

### Через UI

1. Откройте UI: http://localhost:8083/ui/
2. Перейдите в раздел **"Admin login"**
3. Введите:
   - Username: `admin`
   - Password: `admin123`
4. Нажмите **"Admin login"**
5. Скопируйте полученный токен

### Через API

```powershell
# Убедитесь, что port-forward запущен
$apiPod = kubectl get pods -l app=api-server -o jsonpath='{.items[0].metadata.name}'
kubectl port-forward pod/$apiPod 8083:8080

# Вход
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

## Исправление проблемы

Если возникла проблема с хешем пароля, используйте:

```powershell
.\scripts\fix-admin-password.ps1
```

Или выполните SQL файл:

```powershell
$postgresPod = kubectl get pods -l app=postgres -o jsonpath='{.items[0].metadata.name}'
Get-Content scripts/fix-admin-hash.sql | kubectl exec -i $postgresPod -- psql -U user -d 2fa
```

## Важно

⚠️ **Смените пароль после первого входа!**

Для production используйте сложный пароль и не используйте дефолтные учетные данные.
