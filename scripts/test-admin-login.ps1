# Скрипт для тестирования входа администратора

$ErrorActionPreference = "Stop"

Write-Host "=== Тестирование входа администратора ===" -ForegroundColor Cyan

# Проверка данных в базе
Write-Host "`n1. Проверка данных в базе..." -ForegroundColor Yellow
$postgresPod = kubectl get pods -l app=postgres -o jsonpath='{.items[0].metadata.name}'
$dbCheck = kubectl exec $postgresPod -- psql -U user -d 2fa -t -c "SELECT username, status, role, LENGTH(password_hash) as len FROM users WHERE username = 'admin';" 2>&1

Write-Host $dbCheck -ForegroundColor White

if ($dbCheck -notmatch "60") {
    Write-Host "`n⚠ Хеш пароля неправильный! Исправляем..." -ForegroundColor Yellow
    Get-Content scripts/fix-admin-hash.sql | kubectl exec -i $postgresPod -- psql -U user -d 2fa | Out-Null
    Write-Host "✅ Хеш исправлен" -ForegroundColor Green
}

# Проверка API сервера
Write-Host "`n2. Проверка API сервера..." -ForegroundColor Yellow
$apiPod = kubectl get pods -l app=api-server -o jsonpath='{.items[0].metadata.name}'
if (-not $apiPod) {
    Write-Host "❌ API сервер не найден!" -ForegroundColor Red
    exit 1
}
Write-Host "API сервер: $apiPod" -ForegroundColor Green

# Проверка port-forward
Write-Host "`n3. Проверка port-forward..." -ForegroundColor Yellow
$portCheck = netstat -ano | Select-String -Pattern ":8083\s"
if (-not $portCheck) {
    Write-Host "⚠ Port-forward не запущен. Запускаем..." -ForegroundColor Yellow
    Start-Process kubectl -ArgumentList "port-forward","pod/$apiPod","8083:8080" -WindowStyle Hidden
    Start-Sleep -Seconds 3
} else {
    Write-Host "✅ Port-forward работает" -ForegroundColor Green
}

# Тест входа
Write-Host "`n4. Тест входа..." -ForegroundColor Yellow
$body = @{
    username = "admin"
    password = "admin123"
} | ConvertTo-Json

try {
    $response = Invoke-RestMethod -Uri "http://localhost:8083/api/v1/admin/auth/login" `
        -Method POST `
        -Body $body `
        -ContentType "application/json" `
        -ErrorAction Stop
    
    Write-Host "`n✅✅✅ ВХОД УСПЕШЕН! ✅✅✅" -ForegroundColor Green
    Write-Host "`nУчетные данные для админки:" -ForegroundColor Cyan
    Write-Host "  Username: admin" -ForegroundColor White
    Write-Host "  Password: admin123" -ForegroundColor White
    Write-Host "`nAccess Token получен (длина: $($response.access_token.Length) символов)" -ForegroundColor Green
    Write-Host "Expires In: $($response.expires_in) секунд" -ForegroundColor Green
    
} catch {
    Write-Host "`n❌ Ошибка входа:" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    
    Write-Host "`nДиагностика:" -ForegroundColor Yellow
    Write-Host "1. Проверьте хеш в базе:" -ForegroundColor White
    Write-Host "   kubectl exec $postgresPod -- psql -U user -d 2fa -c `"SELECT LENGTH(password_hash) FROM users WHERE username = 'admin';`"" -ForegroundColor Gray
    
    Write-Host "`n2. Проверьте логи API:" -ForegroundColor White
    Write-Host "   kubectl logs -l app=api-server --tail=20" -ForegroundColor Gray
    
    Write-Host "`n3. Перезапустите API сервер:" -ForegroundColor White
    Write-Host "   kubectl delete pod -l app=api-server" -ForegroundColor Gray
    
    Write-Host "`n4. Запустите port-forward вручную:" -ForegroundColor White
    Write-Host "   kubectl port-forward pod/$apiPod 8083:8080" -ForegroundColor Gray
}
