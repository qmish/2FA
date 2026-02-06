# Скрипт для создания RADIUS клиента для Cisco AnyConnect

Write-Host "`n=== СОЗДАНИЕ RADIUS КЛИЕНТА ===" -ForegroundColor Cyan

# Проверяем наличие админского токена
$adminToken = $env:ADMIN_TOKEN
if ([string]::IsNullOrWhiteSpace($adminToken)) {
    Write-Host "⚠ ADMIN_TOKEN не установлен" -ForegroundColor Yellow
    Write-Host "Сначала войдите в админку и получите токен:" -ForegroundColor Yellow
    Write-Host "1. Откройте UI: http://2fa.local/ui/ или http://localhost:30080/ui/" -ForegroundColor White
    Write-Host "2. Войдите как admin (admin/admin123)" -ForegroundColor White
    Write-Host "3. Скопируйте токен из поля 'Admin token'" -ForegroundColor White
    Write-Host "4. Установите: `$env:ADMIN_TOKEN = 'your_token_here'" -ForegroundColor White
    Write-Host "`nИли создайте клиента через SQL напрямую:" -ForegroundColor Yellow
    Write-Host "См. инструкции ниже" -ForegroundColor White
    exit 1
}

# Параметры RADIUS клиента
$clientName = "cisco-anyconnect"
$clientIP = "0.0.0.0/0"  # Принимаем запросы с любого IP (для тестирования)
$clientSecret = "cisco123"  # Секрет для Cisco AnyConnect

Write-Host "`nПараметры клиента:" -ForegroundColor Yellow
Write-Host "  Name: $clientName" -ForegroundColor White
Write-Host "  IP: $clientIP" -ForegroundColor White
Write-Host "  Secret: $clientSecret" -ForegroundColor White

# Создаем через API
Write-Host "`nСоздаю RADIUS клиента через API..." -ForegroundColor Yellow

$body = @{
    name = $clientName
    ip = $clientIP
    secret = $clientSecret
    enabled = $true
} | ConvertTo-Json

try {
    $apiUrl = "http://localhost:30080"
    if (-not (Test-NetConnection -ComputerName localhost -Port 30080 -InformationLevel Quiet -WarningAction SilentlyContinue)) {
        Write-Host "⚠ API недоступен на порту 30080" -ForegroundColor Yellow
        Write-Host "Запустите port-forward: kubectl port-forward svc/api-server 30080:80" -ForegroundColor White
        exit 1
    }

    $response = Invoke-RestMethod -Uri "$apiUrl/api/v1/admin/radius/clients/create" `
        -Method POST `
        -Body $body `
        -ContentType "application/json" `
        -Headers @{Authorization = "Bearer $adminToken"} `
        -ErrorAction Stop

    Write-Host "✅ RADIUS клиент создан!" -ForegroundColor Green
    Write-Host "  ID: $($response.id)" -ForegroundColor White
    Write-Host "  Name: $($response.name)" -ForegroundColor White
    Write-Host "  IP: $($response.ip)" -ForegroundColor White
    Write-Host "  Enabled: $($response.enabled)" -ForegroundColor White

} catch {
    Write-Host "❌ Ошибка создания через API: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "`nСоздаю через SQL напрямую..." -ForegroundColor Yellow
    
    # Создаем через SQL
    $postgresPod = kubectl get pods -l app=postgres -o jsonpath='{.items[0].metadata.name}' 2>&1
    if ($LASTEXITCODE -eq 0) {
        $sql = @"
INSERT INTO radius_clients (id, name, ip, secret, enabled, created_at)
VALUES (
    gen_random_uuid(),
    '$clientName',
    '$clientIP',
    '$clientSecret',
    true,
    NOW()
)
ON CONFLICT (ip) DO UPDATE
SET name = '$clientName',
    secret = '$clientSecret',
    enabled = true;
"@
        $result = kubectl exec $postgresPod -- psql -U user -d 2fa -c $sql 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Host "✅ RADIUS клиент создан через SQL" -ForegroundColor Green
        } else {
            Write-Host "❌ Ошибка создания через SQL: $result" -ForegroundColor Red
        }
    }
}

Write-Host "`n=== ГОТОВО ===" -ForegroundColor Green
Write-Host "`nИспользуйте эти параметры для настройки Cisco AnyConnect:" -ForegroundColor Cyan
Write-Host "  RADIUS Server: <IP_RADIUS_SERVER>:1812" -ForegroundColor White
Write-Host "  Secret: $clientSecret" -ForegroundColor White
Write-Host "  Authentication: PAP" -ForegroundColor White
