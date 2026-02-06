# Финальное решение проблемы входа администратора
# Генерирует правильный хеш и обновляет его в базе

Write-Host "`n=== ФИНАЛЬНОЕ ИСПРАВЛЕНИЕ ПАРОЛЯ АДМИНИСТРАТОРА ===" -ForegroundColor Cyan

# Шаг 1: Генерация правильного хеша
Write-Host "`n[1/4] Генерирую правильный хеш для пароля 'admin123'..." -ForegroundColor Yellow
$hash = docker run --rm -v "${PWD}:/app" -w /app python:3-alpine sh -c "pip install bcrypt > /dev/null 2>&1 && python /app/temp-hash.py" 2>&1 | Select-String -Pattern '\$2[ab]\$' | ForEach-Object { $_.Line.Trim() }

if ([string]::IsNullOrWhiteSpace($hash)) {
    Write-Host "❌ Не удалось сгенерировать хеш" -ForegroundColor Red
    exit 1
}

Write-Host "✅ Хеш сгенерирован: $($hash.Substring(0, 30))..." -ForegroundColor Green

# Шаг 2: Обновление хеша в базе
Write-Host "`n[2/4] Обновляю хеш в базе данных..." -ForegroundColor Yellow
$postgresPod = kubectl get pods -l app=postgres -o jsonpath='{.items[0].metadata.name}' 2>&1
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($postgresPod)) {
    Write-Host "❌ Не удалось найти под PostgreSQL" -ForegroundColor Red
    exit 1
}

$sql = "UPDATE users SET password_hash = '$hash' WHERE username = 'admin' AND role = 'admin';"
$result = kubectl exec $postgresPod -- psql -U user -d 2fa -c $sql 2>&1

if ($LASTEXITCODE -eq 0) {
    Write-Host "✅ Хеш обновлен в базе!" -ForegroundColor Green
} else {
    Write-Host "❌ Ошибка обновления: $result" -ForegroundColor Red
    exit 1
}

# Шаг 3: Перезапуск API сервера
Write-Host "`n[3/4] Перезапускаю API сервер..." -ForegroundColor Yellow
kubectl delete pod -l app=api-server 2>&1 | Out-Null
Start-Sleep -Seconds 20
$apiPods = kubectl get pods -l app=api-server --no-headers 2>&1 | Measure-Object -Line
if ($apiPods.Lines -gt 0) {
    Write-Host "✅ API сервер перезапущен" -ForegroundColor Green
} else {
    Write-Host "❌ Ошибка перезапуска API сервера" -ForegroundColor Red
    exit 1
}

# Шаг 4: Запуск port-forward и тест
Write-Host "`n[4/4] Запускаю port-forward и тестирую вход..." -ForegroundColor Yellow

# Останавливаем старые процессы
Get-Process | Where-Object { 
    $_.ProcessName -eq "kubectl" -or 
    $_.CommandLine -like "*port-forward*8083*"
} | ForEach-Object {
    try {
        Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
    } catch {}
}
Start-Sleep -Seconds 2

$apiPod = kubectl get pods -l app=api-server -o jsonpath='{.items[0].metadata.name}' 2>&1
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($apiPod)) {
    Write-Host "❌ Не удалось найти под API сервера" -ForegroundColor Red
    exit 1
}

Write-Host "Под: $apiPod" -ForegroundColor White
$portForwardScript = "kubectl port-forward pod/$apiPod 8083:8080"
Start-Process powershell -ArgumentList "-NoExit", "-Command", "Write-Host '=== PORT-FORWARD ЗАПУЩЕН ===' -ForegroundColor Green; Write-Host 'Порт: 8083 -> 8080' -ForegroundColor White; Write-Host 'Под: $apiPod' -ForegroundColor White; Write-Host ''; Write-Host 'Оставьте это окно открытым!' -ForegroundColor Yellow; Write-Host ''; $portForwardScript" -WindowStyle Normal

Write-Host "Ожидаю 8 секунд для установки соединения..." -ForegroundColor Yellow
Start-Sleep -Seconds 8

# Проверка доступности API
try {
    $healthCheck = Invoke-RestMethod -Uri "http://localhost:8083/healthz" -Method GET -TimeoutSec 5 -ErrorAction Stop
    Write-Host "✅ API доступен" -ForegroundColor Green
} catch {
    Write-Host "⚠ API пока недоступен, ожидаю еще 5 секунд..." -ForegroundColor Yellow
    Start-Sleep -Seconds 5
    try {
        $healthCheck = Invoke-RestMethod -Uri "http://localhost:8083/healthz" -Method GET -TimeoutSec 5 -ErrorAction Stop
        Write-Host "✅ API доступен" -ForegroundColor Green
    } catch {
        Write-Host "❌ API недоступен: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "`nПопробуйте запустить port-forward вручную:" -ForegroundColor Yellow
        Write-Host "kubectl port-forward pod/$apiPod 8083:8080" -ForegroundColor White
        exit 1
    }
}

# Тест входа
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
    
    Write-Host "`n✅✅✅ ВХОД УСПЕШЕН! ✅✅✅" -ForegroundColor Green
    Write-Host "Access Token получен (длина: $($response.access_token.Length) символов)" -ForegroundColor White
    Write-Host "Expires In: $($response.expires_in) секунд" -ForegroundColor White
    
    Write-Host "`n=== ИНСТРУКЦИИ ===" -ForegroundColor Cyan
    Write-Host "1. Откройте UI: http://localhost:8083/ui/" -ForegroundColor White
    Write-Host "2. Перейдите в раздел 'Admin login'" -ForegroundColor White
    Write-Host "3. Введите:" -ForegroundColor White
    Write-Host "   Username: admin" -ForegroundColor Yellow
    Write-Host "   Password: admin123" -ForegroundColor Yellow
    Write-Host "4. Нажмите 'Login as admin'" -ForegroundColor White
    Write-Host "`n⚠ Важно: Оставьте окно с port-forward открытым!" -ForegroundColor Yellow
    
} catch {
    Write-Host "`n❌ ОШИБКА ВХОДА" -ForegroundColor Red
    
    if ($_.Exception.Response) {
        $statusCode = $_.Exception.Response.StatusCode.value__
        Write-Host "HTTP Status: $statusCode" -ForegroundColor Yellow
        
        $stream = $_.Exception.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($stream)
        $responseBody = $reader.ReadToEnd()
        Write-Host "Ответ сервера: $responseBody" -ForegroundColor Yellow
        
        Write-Host "`nПроверьте логи API:" -ForegroundColor Yellow
        Write-Host "kubectl logs -l app=api-server --tail=50" -ForegroundColor White
    } else {
        Write-Host "Ошибка соединения: $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host "`n⚠ Port-forward может быть не запущен или соединение разорвано" -ForegroundColor Yellow
        Write-Host "Проверьте окно с port-forward" -ForegroundColor White
    }
}

Write-Host "`n=== КОНЕЦ ===" -ForegroundColor Cyan
