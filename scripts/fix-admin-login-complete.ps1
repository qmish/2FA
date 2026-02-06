# Полное решение проблемы входа администратора
# Автоматически исправляет все проблемы и проверяет вход

Write-Host "`n=== ПОЛНОЕ РЕШЕНИЕ ПРОБЛЕМЫ ВХОДА АДМИНИСТРАТОРА ===" -ForegroundColor Cyan

# Шаг 1: Проверка данных в базе
Write-Host "`n[1/5] Проверяю данные администратора в базе..." -ForegroundColor Yellow
$postgresPod = kubectl get pods -l app=postgres -o jsonpath='{.items[0].metadata.name}' 2>&1
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($postgresPod)) {
    Write-Host "❌ Не удалось найти под PostgreSQL" -ForegroundColor Red
    exit 1
}

$correctHash = '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy'
$currentHash = kubectl exec $postgresPod -- psql -U user -d 2fa -t -c "SELECT password_hash FROM users WHERE username = 'admin' AND role = 'admin';" 2>&1 | Select-String -Pattern '\$2a\$' | ForEach-Object { $_.Line.Trim() }

if ([string]::IsNullOrWhiteSpace($currentHash)) {
    Write-Host "❌ Администратор не найден в базе!" -ForegroundColor Red
    Write-Host "Создаю администратора..." -ForegroundColor Yellow
    $sql = "INSERT INTO users (id, username, status, role, password_hash, created_at, updated_at) VALUES (gen_random_uuid(), 'admin', 'active', 'admin', '$correctHash', NOW(), NOW()) ON CONFLICT (username, role) DO UPDATE SET password_hash = '$correctHash', status = 'active', updated_at = NOW();"
    kubectl exec $postgresPod -- psql -U user -d 2fa -c $sql 2>&1 | Out-Null
    Write-Host "✅ Администратор создан/обновлен" -ForegroundColor Green
} elseif ($currentHash -ne $correctHash) {
    Write-Host "⚠ Хеш неправильный, исправляю..." -ForegroundColor Yellow
    $sql = "UPDATE users SET password_hash = '$correctHash' WHERE username = 'admin' AND role = 'admin';"
    kubectl exec $postgresPod -- psql -U user -d 2fa -c $sql 2>&1 | Out-Null
    Write-Host "✅ Хеш исправлен" -ForegroundColor Green
} else {
    Write-Host "✅ Хеш правильный" -ForegroundColor Green
}

# Шаг 2: Перезапуск API сервера
Write-Host "`n[2/5] Перезапускаю API сервер..." -ForegroundColor Yellow
kubectl delete pod -l app=api-server 2>&1 | Out-Null
Start-Sleep -Seconds 20
$apiPods = kubectl get pods -l app=api-server --no-headers 2>&1 | Measure-Object -Line
if ($apiPods.Lines -gt 0) {
    Write-Host "✅ API сервер перезапущен" -ForegroundColor Green
} else {
    Write-Host "❌ Ошибка перезапуска API сервера" -ForegroundColor Red
    exit 1
}

# Шаг 3: Остановка старых port-forward процессов
Write-Host "`n[3/5] Останавливаю старые port-forward процессы..." -ForegroundColor Yellow
Get-Process | Where-Object { 
    $_.ProcessName -eq "kubectl" -or 
    $_.CommandLine -like "*port-forward*8083*"
} | ForEach-Object {
    try {
        Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
    } catch {}
}
Start-Sleep -Seconds 2
Write-Host "✅ Старые процессы остановлены" -ForegroundColor Green

# Шаг 4: Запуск port-forward
Write-Host "`n[4/5] Запускаю port-forward..." -ForegroundColor Yellow
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
Write-Host "Проверяю доступность API..." -ForegroundColor Yellow
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

# Шаг 5: Тест входа
Write-Host "`n[5/5] Тестирую вход администратора..." -ForegroundColor Yellow
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
    Write-Host "`nAccess Token получен (длина: $($response.access_token.Length) символов)" -ForegroundColor White
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
