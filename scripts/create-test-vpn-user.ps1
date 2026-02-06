# Скрипт для создания тестового пользователя для VPN с телефоном

Write-Host "`n=== СОЗДАНИЕ ТЕСТОВОГО ПОЛЬЗОВАТЕЛЯ ДЛЯ VPN ===" -ForegroundColor Cyan

$postgresPod = kubectl get pods -l app=postgres -o jsonpath='{.items[0].metadata.name}' 2>&1
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($postgresPod)) {
    Write-Host "❌ Не удалось найти под PostgreSQL" -ForegroundColor Red
    exit 1
}

# Генерируем хеш пароля для тестового пользователя
Write-Host "`nГенерирую хеш пароля..." -ForegroundColor Yellow
$password = "test123"
$hash = docker run --rm -v "${PWD}:/app" -w /app python:3-alpine sh -c "pip install bcrypt > /dev/null 2>&1 && python -c 'import bcrypt; print(bcrypt.hashpw(b\"$password\", bcrypt.gensalt()).decode())'" 2>&1 | Select-String -Pattern '\$2[ab]\$' | ForEach-Object { $_.Line.Trim() }

if ([string]::IsNullOrWhiteSpace($hash)) {
    Write-Host "❌ Не удалось сгенерировать хеш пароля" -ForegroundColor Red
    exit 1
}

Write-Host "✅ Хеш пароля сгенерирован" -ForegroundColor Green

# Создаем тестового пользователя
Write-Host "`nСоздаю тестового пользователя..." -ForegroundColor Yellow
$testUsername = "vpnuser"
$testPhone = "+79991234567"  # Тестовый номер телефона

$sql = @"
INSERT INTO users (id, username, status, role, password_hash, phone, created_at, updated_at)
VALUES (
    gen_random_uuid(),
    '$testUsername',
    'active',
    'user',
    '$hash',
    '$testPhone',
    NOW(),
    NOW()
)
ON CONFLICT (username) DO UPDATE
SET password_hash = '$hash',
    phone = '$testPhone',
    status = 'active',
    updated_at = NOW();
"@

$result = kubectl exec $postgresPod -- psql -U user -d 2fa -c $sql 2>&1

if ($LASTEXITCODE -eq 0) {
    Write-Host "✅ Тестовый пользователь создан/обновлен" -ForegroundColor Green
    Write-Host "`nУчетные данные:" -ForegroundColor Cyan
    Write-Host "  Username: $testUsername" -ForegroundColor White
    Write-Host "  Password: $password" -ForegroundColor White
    Write-Host "  Phone: $testPhone" -ForegroundColor White
} else {
    Write-Host "❌ Ошибка создания пользователя: $result" -ForegroundColor Red
    exit 1
}

Write-Host "`n=== ГОТОВО ===" -ForegroundColor Green
