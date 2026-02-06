# Скрипт для создания VPN пользователя напрямую через SQL
# Использует готовый хеш пароля или генерирует новый

Write-Host "`n=== СОЗДАНИЕ VPN ПОЛЬЗОВАТЕЛЯ ЧЕРЕЗ SQL ===" -ForegroundColor Cyan

$postgresPod = kubectl get pods -l app=postgres -o jsonpath='{.items[0].metadata.name}' 2>&1
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($postgresPod)) {
    Write-Host "❌ Не удалось найти под PostgreSQL" -ForegroundColor Red
    exit 1
}

Write-Host "Под PostgreSQL: $postgresPod" -ForegroundColor Green

# Параметры пользователя
Write-Host "`nПараметры пользователя:" -ForegroundColor Yellow
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

Write-Host "`nГенерирую хеш пароля..." -ForegroundColor Yellow

# Генерируем хеш через Python в Docker
$hashOutput = docker run --rm python:3-alpine sh -c "pip install bcrypt > /dev/null 2>&1 && python -c 'import bcrypt; print(bcrypt.hashpw(b\"$password\", bcrypt.gensalt()).decode())'" 2>&1

# Извлекаем хеш из вывода
$hash = $null
foreach ($line in $hashOutput) {
    if ($line -match '\$2[ab]\$[0-9]+\$[A-Za-z0-9\./]+') {
        $hash = $line.Trim()
        break
    }
}

if ([string]::IsNullOrWhiteSpace($hash)) {
    Write-Host "❌ Не удалось сгенерировать хеш пароля" -ForegroundColor Red
    Write-Host "Вывод Docker: $hashOutput" -ForegroundColor Yellow
    Write-Host "`nПопробуйте создать пользователя через API: .\scripts\create-vpn-user-api.ps1" -ForegroundColor Yellow
    exit 1
}

Write-Host "✅ Хеш пароля сгенерирован" -ForegroundColor Green

# Создаем пользователя
Write-Host "`nСоздаю пользователя в базе данных..." -ForegroundColor Yellow

$sql = @"
INSERT INTO users (id, username, status, role, password_hash, phone, created_at, updated_at)
VALUES (
    gen_random_uuid(),
    '$username',
    'active',
    'user',
    '$hash',
    '$phone',
    NOW(),
    NOW()
)
ON CONFLICT (username) DO UPDATE
SET password_hash = '$hash',
    phone = '$phone',
    status = 'active',
    updated_at = NOW();
"@

$result = kubectl exec $postgresPod -- psql -U user -d 2fa -c $sql 2>&1

if ($LASTEXITCODE -eq 0) {
    Write-Host "`n✅✅✅ ПОЛЬЗОВАТЕЛЬ СОЗДАН! ✅✅✅" -ForegroundColor Green
    Write-Host "`nУчетные данные:" -ForegroundColor Cyan
    Write-Host "  Username: $username" -ForegroundColor White
    Write-Host "  Password: $password" -ForegroundColor White
    Write-Host "  Phone: $phone" -ForegroundColor White
    
    Write-Host "`nПроверяю созданного пользователя..." -ForegroundColor Yellow
    kubectl exec $postgresPod -- psql -U user -d 2fa -c "SELECT username, status, phone FROM users WHERE username = '$username';" 2>&1 | Select-Object -Last 4
    
    Write-Host "`nТеперь можно тестировать подключение через Cisco AnyConnect!" -ForegroundColor Green
} else {
    Write-Host "`n❌ Ошибка создания пользователя: $result" -ForegroundColor Red
    Write-Host "`nПопробуйте создать пользователя через API: .\scripts\create-vpn-user-api.ps1" -ForegroundColor Yellow
}

Write-Host "`n=== КОНЕЦ ===" -ForegroundColor Cyan
