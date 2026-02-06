# Скрипт для тестирования входа администратора
# Автоматически запускает port-forward и проверяет вход

Write-Host "`n=== ТЕСТ ВХОДА АДМИНИСТРАТОРА ===" -ForegroundColor Cyan

# Получаем под API сервера
$apiPod = kubectl get pods -l app=api-server -o jsonpath='{.items[0].metadata.name}' 2>&1
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($apiPod)) {
    Write-Host "❌ Не удалось найти под API сервера" -ForegroundColor Red
    exit 1
}

Write-Host "Под API сервера: $apiPod" -ForegroundColor Green

# Проверяем, запущен ли port-forward
$portForwardProcess = Get-Process | Where-Object { 
    $_.CommandLine -like "*kubectl port-forward*$apiPod*8083*" -or
    $_.ProcessName -eq "kubectl" -and $_.CommandLine -like "*port-forward*8083*"
} | Select-Object -First 1

if ($portForwardProcess) {
    Write-Host "⚠ Найден существующий процесс port-forward (PID: $($portForwardProcess.Id))" -ForegroundColor Yellow
    Write-Host "Останавливаю старый процесс..." -ForegroundColor Yellow
    Stop-Process -Id $portForwardProcess.Id -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
}

# Запускаем port-forward в отдельном окне
Write-Host "`nЗапускаю port-forward в отдельном окне PowerShell..." -ForegroundColor Yellow
$portForwardScript = "kubectl port-forward pod/$apiPod 8083:8080"
Start-Process powershell -ArgumentList "-NoExit", "-Command", "Write-Host 'Port-forward запущен на порту 8083' -ForegroundColor Green; Write-Host 'Оставьте это окно открытым!' -ForegroundColor Yellow; Write-Host ''; $portForwardScript" -WindowStyle Normal

Write-Host "Ожидаю 5 секунд для установки соединения..." -ForegroundColor Yellow
Start-Sleep -Seconds 5

# Проверяем доступность API
Write-Host "`nПроверяю доступность API..." -ForegroundColor Yellow
try {
    $healthCheck = Invoke-RestMethod -Uri "http://localhost:8083/healthz" -Method GET -TimeoutSec 5 -ErrorAction Stop
    Write-Host "✅ API доступен" -ForegroundColor Green
} catch {
    Write-Host "❌ API недоступен: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "`nПопробуйте запустить port-forward вручную:" -ForegroundColor Yellow
    Write-Host "kubectl port-forward pod/$apiPod 8083:8080" -ForegroundColor White
    exit 1
}

# Проверяем данные в базе
Write-Host "`nПроверяю данные администратора в базе..." -ForegroundColor Yellow
$postgresPod = kubectl get pods -l app=postgres -o jsonpath='{.items[0].metadata.name}' 2>&1
if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($postgresPod)) {
    $dbCheck = kubectl exec $postgresPod -- psql -U user -d 2fa -t -c "SELECT username, status, role, LENGTH(password_hash) as len FROM users WHERE username = 'admin' AND role = 'admin';" 2>&1
    if ($dbCheck -match "admin.*active.*admin.*60") {
        Write-Host "✅ Данные администратора корректны" -ForegroundColor Green
    } else {
        Write-Host "⚠ Данные администратора:" -ForegroundColor Yellow
        Write-Host $dbCheck -ForegroundColor White
    }
}

# Тестируем вход
Write-Host "`nТестирую вход администратора..." -ForegroundColor Yellow
$body = @{
    username = "admin"
    password = "admin123"
} | ConvertTo-Json

try {
    $response = Invoke-RestMethod -Uri "http://localhost:8083/api/v1/admin/auth/login" `
        -Method POST `
        -Body $body `
        -ContentType "application/json" `
        -TimeoutSec 10 `
        -ErrorAction Stop
    
    Write-Host "`n✅ ВХОД УСПЕШЕН!" -ForegroundColor Green
    Write-Host "Access Token получен (длина: $($response.access_token.Length) символов)" -ForegroundColor White
    Write-Host "Expires In: $($response.expires_in) секунд" -ForegroundColor White
    Write-Host "`nТеперь вы можете войти в UI:" -ForegroundColor Cyan
    Write-Host "http://localhost:8083/ui/" -ForegroundColor White
    Write-Host "`nУчетные данные:" -ForegroundColor Cyan
    Write-Host "  Username: admin" -ForegroundColor White
    Write-Host "  Password: admin123" -ForegroundColor White
    
} catch {
    Write-Host "`n❌ ОШИБКА ВХОДА" -ForegroundColor Red
    
    if ($_.Exception.Response) {
        $statusCode = $_.Exception.Response.StatusCode.value__
        Write-Host "HTTP Status: $statusCode" -ForegroundColor Yellow
        
        $stream = $_.Exception.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($stream)
        $responseBody = $reader.ReadToEnd()
        Write-Host "Ответ сервера: $responseBody" -ForegroundColor Yellow
        
        if ($statusCode -eq 401) {
            Write-Host "`n⚠ Проблема с аутентификацией. Возможные причины:" -ForegroundColor Yellow
            Write-Host "1. Неправильный пароль в базе данных" -ForegroundColor White
            Write-Host "2. API сервер не перечитал данные из базы" -ForegroundColor White
            Write-Host "`nПопробуйте:" -ForegroundColor Yellow
            Write-Host "1. Перезапустить API сервер: kubectl delete pod -l app=api-server" -ForegroundColor White
            Write-Host "2. Проверить хеш пароля в базе" -ForegroundColor White
            Write-Host "3. Исправить хеш через: .\scripts\fix-admin-password.ps1" -ForegroundColor White
        }
    } else {
        Write-Host "Ошибка соединения: $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host "`n⚠ Port-forward может быть не запущен или соединение разорвано" -ForegroundColor Yellow
        Write-Host "Проверьте окно с port-forward и перезапустите его при необходимости" -ForegroundColor White
    }
}

Write-Host "`n=== КОНЕЦ ТЕСТА ===" -ForegroundColor Cyan
