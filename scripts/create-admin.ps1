# Скрипт для создания администратора

$ErrorActionPreference = "Stop"

Write-Host "=== Создание администратора ===" -ForegroundColor Cyan

# Проверка наличия API сервера
$apiPod = kubectl get pods -l app=api-server -o jsonpath='{.items[0].metadata.name}'
if (-not $apiPod) {
    Write-Host "Ошибка: API сервер не запущен!" -ForegroundColor Red
    exit 1
}

Write-Host "`nAPI сервер найден: $apiPod" -ForegroundColor Green

# Запрос данных администратора
Write-Host "`nВведите данные администратора:" -ForegroundColor Yellow
$username = Read-Host "Username"
$password = Read-Host "Password" -AsSecureString
$passwordPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($password))
$email = Read-Host "Email (опционально)"

# Проверка port-forward
$port = 8083
$check = netstat -ano | Select-String -Pattern ":$port\s"
if (-not $check) {
    Write-Host "`n⚠ Port-forward не запущен на порту $port" -ForegroundColor Yellow
    Write-Host "Запустите в отдельном терминале:" -ForegroundColor Yellow
    Write-Host "  kubectl port-forward pod/$apiPod $port`:8080" -ForegroundColor White
    Write-Host "`nИли используйте скрипт:" -ForegroundColor Yellow
    Write-Host "  .\scripts\start-ui.ps1" -ForegroundColor White
    Write-Host "`nНажмите Enter после запуска port-forward..." -ForegroundColor Yellow
    Read-Host
}

# Создание администратора через API
Write-Host "`nСоздание администратора..." -ForegroundColor Yellow

$body = @{
    username = $username
    password = $passwordPlain
    email = $email
    role = "admin"
    status = "active"
} | ConvertTo-Json

try {
    $response = Invoke-RestMethod -Uri "http://localhost:$port/api/v1/admin/users/create" `
        -Method POST `
        -Body $body `
        -ContentType "application/json" `
        -Headers @{
            "Authorization" = "Bearer YOUR_ADMIN_TOKEN"
        } `
        -ErrorAction Stop
    
    Write-Host "`n✅ Администратор успешно создан!" -ForegroundColor Green
    Write-Host "Username: $($response.username)" -ForegroundColor White
    Write-Host "Email: $($response.email)" -ForegroundColor White
    Write-Host "Role: $($response.role)" -ForegroundColor White
    Write-Host "Status: $($response.status)" -ForegroundColor White
    
} catch {
    Write-Host "`n❌ Ошибка создания администратора:" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    
    if ($_.Exception.Response) {
        $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
        $responseBody = $reader.ReadToEnd()
        Write-Host "Ответ сервера: $responseBody" -ForegroundColor Yellow
    }
    
    Write-Host "`nПримечание: Для создания первого администратора может потребоваться:" -ForegroundColor Yellow
    Write-Host "1. Создать администратора напрямую в базе данных" -ForegroundColor White
    Write-Host "2. Или использовать SQL скрипт (см. scripts/create-admin.sql)" -ForegroundColor White
}
