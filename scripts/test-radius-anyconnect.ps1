# Скрипт для тестирования RADIUS с Cisco AnyConnect
# Использует radclient для отправки RADIUS запросов

Write-Host "`n=== ТЕСТИРОВАНИЕ RADIUS С CISCO ANYCONNECT ===" -ForegroundColor Cyan

# Проверка наличия radclient
Write-Host "`n[1/5] Проверяю наличие radclient..." -ForegroundColor Yellow
$radclientPath = Get-Command radclient -ErrorAction SilentlyContinue
if (-not $radclientPath) {
    Write-Host "⚠ radclient не найден. Установите freeradius-utils или используйте Docker" -ForegroundColor Yellow
    Write-Host "`nАльтернатива: используйте Docker для тестирования" -ForegroundColor Yellow
    Write-Host "docker run --rm -it --network host freeradius/freeradius-server:latest radclient ..." -ForegroundColor White
} else {
    Write-Host "✅ radclient найден: $($radclientPath.Source)" -ForegroundColor Green
}

# Получение адреса RADIUS сервера
Write-Host "`n[2/5] Получаю адрес RADIUS сервера..." -ForegroundColor Yellow
$radiusPod = kubectl get pods -l app=radius-server -o jsonpath='{.items[0].metadata.name}' 2>&1
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($radiusPod)) {
    Write-Host "❌ RADIUS сервер не найден" -ForegroundColor Red
    exit 1
}

Write-Host "Под RADIUS: $radiusPod" -ForegroundColor White

# Проверка Service
$radiusService = kubectl get svc radius-server -o jsonpath='{.metadata.name}' 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "⚠ Service для RADIUS не найден, создаю..." -ForegroundColor Yellow
    kubectl apply -f docs/k8s/radius-service.yaml 2>&1 | Out-Null
    Start-Sleep -Seconds 3
}

# Получение секрета RADIUS
Write-Host "`n[3/5] Получаю секрет RADIUS..." -ForegroundColor Yellow
$postgresPod = kubectl get pods -l app=postgres -o jsonpath='{.items[0].metadata.name}' 2>&1
$radiusSecret = kubectl get configmap api-config -o jsonpath='{.data.RADIUS_SECRET}' 2>&1
if ([string]::IsNullOrWhiteSpace($radiusSecret)) {
    $radiusSecret = "secret"  # Значение по умолчанию
    Write-Host "⚠ Секрет не найден, использую значение по умолчанию: secret" -ForegroundColor Yellow
} else {
    Write-Host "✅ Секрет получен" -ForegroundColor Green
}

# Проверка пользователя для тестирования
Write-Host "`n[4/5] Проверяю тестового пользователя..." -ForegroundColor Yellow
$testUser = kubectl exec $postgresPod -- psql -U user -d 2fa -t -c "SELECT username FROM users WHERE status = 'active' AND phone IS NOT NULL AND phone != '' LIMIT 1;" 2>&1 | ForEach-Object { $_.Trim() }

if ([string]::IsNullOrWhiteSpace($testUser)) {
    Write-Host "⚠ Тестовый пользователь с телефоном не найден" -ForegroundColor Yellow
    Write-Host "Создайте пользователя через админку или используйте существующего" -ForegroundColor White
    Write-Host "`nПроверяю всех пользователей..." -ForegroundColor Yellow
    kubectl exec $postgresPod -- psql -U user -d 2fa -c "SELECT username, status, phone FROM users LIMIT 5;" 2>&1 | Select-Object -Last 7
    exit 1
} else {
    Write-Host "✅ Тестовый пользователь: $testUser" -ForegroundColor Green
}

# Получение адреса для подключения
Write-Host "`n[5/5] Настраиваю подключение..." -ForegroundColor Yellow

# Проверяем, доступен ли RADIUS через port-forward или Service
$radiusHost = "localhost"
$radiusPort = 1812

Write-Host "`n=== ИНСТРУКЦИИ ПО ТЕСТИРОВАНИЮ ===" -ForegroundColor Cyan
Write-Host "`n1. Запустите port-forward для RADIUS сервера:" -ForegroundColor Yellow
Write-Host "   kubectl port-forward svc/radius-server 1812:1812" -ForegroundColor White
Write-Host "`n2. В отдельном терминале выполните тест:" -ForegroundColor Yellow
Write-Host "   radclient -x $radiusHost`:$radiusPort auth $radiusSecret" -ForegroundColor White
Write-Host "`n3. Или используйте файл с запросом:" -ForegroundColor Yellow
Write-Host "   Создайте файл radius-test.txt с содержимым:" -ForegroundColor White
Write-Host "   User-Name = $testUser" -ForegroundColor Gray
Write-Host "   User-Password = password123" -ForegroundColor Gray
Write-Host "   NAS-IP-Address = 127.0.0.1" -ForegroundColor Gray
Write-Host "`n   Затем выполните:" -ForegroundColor White
Write-Host "   radclient -x $radiusHost`:$radiusPort auth $radiusSecret < radius-test.txt" -ForegroundColor White

Write-Host "`n=== ФОРМАТ ПАРОЛЯ ДЛЯ 2FA ===" -ForegroundColor Cyan
Write-Host "RADIUS сервер поддерживает двухфакторную аутентификацию:" -ForegroundColor Yellow
Write-Host "Формат пароля: <password>:<otp_code>" -ForegroundColor White
Write-Host "Пример: password123:123456" -ForegroundColor Gray
Write-Host "`nПроцесс:" -ForegroundColor Yellow
Write-Host "1. Первый запрос: User-Password = password123" -ForegroundColor White
Write-Host "   → Сервер отправит OTP код и вернет Access-Reject с сообщением 'otp_required'" -ForegroundColor Gray
Write-Host "2. Второй запрос: User-Password = password123:123456" -ForegroundColor White
Write-Host "   → Сервер проверит OTP и вернет Access-Accept при успехе" -ForegroundColor Gray

Write-Host "`n=== НАСТРОЙКА CISCO ANYCONNECT ===" -ForegroundColor Cyan
Write-Host "`nДля настройки Cisco AnyConnect:" -ForegroundColor Yellow
Write-Host "1. Сервер RADIUS: $radiusHost`:$radiusPort" -ForegroundColor White
Write-Host "2. Секрет: $radiusSecret" -ForegroundColor White
Write-Host "3. Формат аутентификации: PAP (Password Authentication Protocol)" -ForegroundColor White
Write-Host "4. Пользователь должен иметь телефон для получения OTP" -ForegroundColor White

Write-Host "`n=== ПРОВЕРКА ЛОГОВ ===" -ForegroundColor Cyan
Write-Host "После тестирования проверьте логи:" -ForegroundColor Yellow
Write-Host "kubectl logs -l app=radius-server --tail=50" -ForegroundColor White
Write-Host "`nПроверьте историю входов:" -ForegroundColor Yellow
Write-Host "kubectl exec $postgresPod -- psql -U user -d 2fa -c `"SELECT username, result, created_at FROM login_history WHERE channel = 'vpn' ORDER BY created_at DESC LIMIT 10;`"" -ForegroundColor White

Write-Host "`n=== КОНЕЦ ===" -ForegroundColor Cyan
