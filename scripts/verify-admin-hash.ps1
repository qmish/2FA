# Скрипт для проверки и исправления хеша пароля администратора

Write-Host "`n=== ПРОВЕРКА И ИСПРАВЛЕНИЕ ХЕША ПАРОЛЯ ===" -ForegroundColor Cyan

$postgresPod = kubectl get pods -l app=postgres -o jsonpath='{.items[0].metadata.name}' 2>&1
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($postgresPod)) {
    Write-Host "❌ Не удалось найти под PostgreSQL" -ForegroundColor Red
    exit 1
}

Write-Host "Под PostgreSQL: $postgresPod" -ForegroundColor Green

# Получаем текущий хеш
Write-Host "`nПолучаю текущий хеш из базы..." -ForegroundColor Yellow
$currentHash = kubectl exec $postgresPod -- psql -U user -d 2fa -t -c "SELECT password_hash FROM users WHERE username = 'admin' AND role = 'admin';" 2>&1 | Select-String -Pattern '\$2a\$' | ForEach-Object { $_.Line.Trim() }

if ([string]::IsNullOrWhiteSpace($currentHash)) {
    Write-Host "❌ Хеш не найден в базе!" -ForegroundColor Red
    exit 1
}

Write-Host "Текущий хеш: $($currentHash.Substring(0, [Math]::Min(30, $currentHash.Length)))..." -ForegroundColor White
Write-Host "Длина: $($currentHash.Length)" -ForegroundColor White

# Правильный хеш для пароля "admin123"
$correctHash = '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy'

if ($currentHash -eq $correctHash) {
    Write-Host "`n✅ Хеш правильный!" -ForegroundColor Green
    Write-Host "Проблема может быть в другом месте." -ForegroundColor Yellow
    Write-Host "`nПопробуйте:" -ForegroundColor Yellow
    Write-Host "1. Перезапустить API сервер: kubectl delete pod -l app=api-server" -ForegroundColor White
    Write-Host "2. Проверить логи API: kubectl logs -l app=api-server --tail=50" -ForegroundColor White
} else {
    Write-Host "`n⚠ Хеш не соответствует ожидаемому!" -ForegroundColor Yellow
    Write-Host "Ожидаемый: $($correctHash.Substring(0, 30))..." -ForegroundColor White
    Write-Host "Текущий:   $($currentHash.Substring(0, [Math]::Min(30, $currentHash.Length)))..." -ForegroundColor White
    
    Write-Host "`nИсправляю хеш..." -ForegroundColor Yellow
    
    # Создаем SQL для исправления
    $sql = "UPDATE users SET password_hash = '$correctHash' WHERE username = 'admin' AND role = 'admin';"
    
    $result = kubectl exec $postgresPod -- psql -U user -d 2fa -c $sql 2>&1
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✅ Хеш обновлен!" -ForegroundColor Green
        
        Write-Host "`nПерезапускаю API сервер..." -ForegroundColor Yellow
        kubectl delete pod -l app=api-server 2>&1 | Out-Null
        Start-Sleep -Seconds 15
        
        Write-Host "✅ API сервер перезапущен" -ForegroundColor Green
        Write-Host "`nТеперь попробуйте войти снова:" -ForegroundColor Yellow
        Write-Host "  Username: admin" -ForegroundColor White
        Write-Host "  Password: admin123" -ForegroundColor White
    } else {
        Write-Host "❌ Ошибка при обновлении хеша:" -ForegroundColor Red
        Write-Host $result -ForegroundColor Yellow
    }
}

Write-Host "`n=== КОНЕЦ ===" -ForegroundColor Cyan
