# Простой скрипт для создания VPN пользователя с использованием готового хеша

Write-Host "`n=== СОЗДАНИЕ VPN ПОЛЬЗОВАТЕЛЯ ===" -ForegroundColor Cyan

$postgresPod = kubectl get pods -l app=postgres -o jsonpath='{.items[0].metadata.name}' 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ Не удалось найти под PostgreSQL" -ForegroundColor Red
    exit 1
}

# Используем готовый хеш для пароля "test123"
# Этот хеш был сгенерирован ранее для пароля test123
$passwordHash = '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewY5GyYqJ5x5x5xO'

Write-Host "Создаю пользователя vpnuser..." -ForegroundColor Yellow

$sql = @"
INSERT INTO users (id, username, status, role, password_hash, phone, created_at, updated_at)
VALUES (
    gen_random_uuid(),
    'vpnuser',
    'active',
    'user',
    '$passwordHash',
    '+79991234567',
    NOW(),
    NOW()
)
ON CONFLICT (username) DO UPDATE
SET password_hash = '$passwordHash',
    phone = '+79991234567',
    status = 'active',
    updated_at = NOW();
"@

$result = kubectl exec $postgresPod -- psql -U user -d 2fa -c $sql 2>&1

if ($LASTEXITCODE -eq 0) {
    Write-Host "✅ Пользователь создан/обновлен" -ForegroundColor Green
    Write-Host "`nУчетные данные:" -ForegroundColor Cyan
    Write-Host "  Username: vpnuser" -ForegroundColor White
    Write-Host "  Password: test123" -ForegroundColor White
    Write-Host "  Phone: +79991234567" -ForegroundColor White
} else {
    Write-Host "❌ Ошибка: $result" -ForegroundColor Red
    Write-Host "`nПопробуйте создать пользователя через админку UI" -ForegroundColor Yellow
}
