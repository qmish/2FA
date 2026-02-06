# Простой скрипт для создания VPN пользователя через API

Write-Host "`n=== СОЗДАНИЕ VPN ПОЛЬЗОВАТЕЛЯ ЧЕРЕЗ API ===" -ForegroundColor Cyan

# Проверка доступности API
$apiUrl = "http://localhost:30080"
if (-not (Test-NetConnection -ComputerName localhost -Port 30080 -InformationLevel Quiet -WarningAction SilentlyContinue)) {
    Write-Host "⚠ API недоступен на порту 30080" -ForegroundColor Yellow
    Write-Host "Запустите port-forward: kubectl port-forward svc/api-server 30080:80" -ForegroundColor White
    Write-Host "Или используйте другой порт, если port-forward запущен на другом порту" -ForegroundColor White
    $apiUrl = Read-Host "Введите URL API (например, http://localhost:8083)"
}

# Получение админского токена
Write-Host "`n[1/3] Получение админского токена..." -ForegroundColor Yellow
Write-Host "Войдите в админку и получите токен:" -ForegroundColor White
Write-Host "1. Откройте: $apiUrl/ui/" -ForegroundColor Cyan
Write-Host "2. Войдите как admin (admin/admin123)" -ForegroundColor Cyan
Write-Host "3. Скопируйте токен из поля 'Admin token'" -ForegroundColor Cyan
Write-Host ""

$adminToken = Read-Host "Вставьте админский токен"

if ([string]::IsNullOrWhiteSpace($adminToken)) {
    Write-Host "❌ Токен не введен" -ForegroundColor Red
    exit 1
}

Write-Host "✅ Токен получен" -ForegroundColor Green

# Параметры пользователя
Write-Host "`n[2/3] Параметры пользователя..." -ForegroundColor Yellow
$username = Read-Host "Username (по умолчанию: vpnuser)"
if ([string]::IsNullOrWhiteSpace($username)) {
    $username = "vpnuser"
}

$password = Read-Host "Password (по умолчанию: test123)"
if ([string]::IsNullOrWhiteSpace($password)) {
    $password = "test123"
}

$phone = Read-Host "Phone (по умолчанию: +79991234567)"
if ([string]::IsNullOrWhiteSpace($phone)) {
    $phone = "+79991234567"
}

$email = Read-Host "Email (необязательно, нажмите Enter чтобы пропустить)"

Write-Host "`nСоздаю пользователя:" -ForegroundColor Yellow
Write-Host "  Username: $username" -ForegroundColor White
Write-Host "  Password: $password" -ForegroundColor White
Write-Host "  Phone: $phone" -ForegroundColor White
if (-not [string]::IsNullOrWhiteSpace($email)) {
    Write-Host "  Email: $email" -ForegroundColor White
}

# Создание пользователя через API
Write-Host "`n[3/3] Создание пользователя через API..." -ForegroundColor Yellow

$body = @{
    username = $username
    password = $password
    phone = $phone
    status = "active"
    role = "user"
}

if (-not [string]::IsNullOrWhiteSpace($email)) {
    $body.email = $email
}

$bodyJson = $body | ConvertTo-Json

try {
    $response = Invoke-RestMethod -Uri "$apiUrl/api/v1/admin/users/create" `
        -Method POST `
        -Body $bodyJson `
        -ContentType "application/json" `
        -Headers @{Authorization = "Bearer $adminToken"} `
        -ErrorAction Stop

    Write-Host "`n✅✅✅ ПОЛЬЗОВАТЕЛЬ СОЗДАН! ✅✅✅" -ForegroundColor Green
    Write-Host "`nДанные пользователя:" -ForegroundColor Cyan
    Write-Host "  ID: $($response.id)" -ForegroundColor White
    Write-Host "  Username: $($response.username)" -ForegroundColor White
    Write-Host "  Status: $($response.status)" -ForegroundColor White
    Write-Host "  Role: $($response.role)" -ForegroundColor White
    if ($response.phone) {
        Write-Host "  Phone: $($response.phone)" -ForegroundColor White
    }
    if ($response.email) {
        Write-Host "  Email: $($response.email)" -ForegroundColor White
    }

    Write-Host "`nТеперь можно тестировать подключение через Cisco AnyConnect!" -ForegroundColor Green

} catch {
    Write-Host "`n❌ ОШИБКА СОЗДАНИЯ ПОЛЬЗОВАТЕЛЯ" -ForegroundColor Red
    
    if ($_.Exception.Response) {
        $statusCode = $_.Exception.Response.StatusCode.value__
        Write-Host "HTTP Status: $statusCode" -ForegroundColor Yellow
        
        $stream = $_.Exception.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($stream)
        $responseBody = $reader.ReadToEnd()
        Write-Host "Ответ сервера: $responseBody" -ForegroundColor Yellow
        
        if ($statusCode -eq 401) {
            Write-Host "`n⚠ Проблема с авторизацией. Проверьте токен." -ForegroundColor Yellow
        } elseif ($statusCode -eq 403) {
            Write-Host "`n⚠ Недостаточно прав. Убедитесь, что вы вошли как admin." -ForegroundColor Yellow
        } elseif ($statusCode -eq 409) {
            Write-Host "`n⚠ Пользователь с таким username уже существует." -ForegroundColor Yellow
        }
    } else {
        Write-Host "Ошибка соединения: $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host "`nПроверьте:" -ForegroundColor Yellow
        Write-Host "1. API доступен: $apiUrl/healthz" -ForegroundColor White
        Write-Host "2. Port-forward запущен" -ForegroundColor White
        Write-Host "3. Токен правильный" -ForegroundColor White
    }
}

Write-Host "`n=== КОНЕЦ ===" -ForegroundColor Cyan
