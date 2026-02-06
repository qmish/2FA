# Скрипт для исправления пароля администратора

$ErrorActionPreference = "Stop"

Write-Host "=== Исправление пароля администратора ===" -ForegroundColor Cyan

$postgresPod = kubectl get pods -l app=postgres -o jsonpath='{.items[0].metadata.name}'
if (-not $postgresPod) {
    Write-Host "Ошибка: PostgreSQL не найден" -ForegroundColor Red
    exit 1
}

Write-Host "`nPostgreSQL найден: $postgresPod" -ForegroundColor Green

# Хеш для пароля "admin123"
$correctHash = '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy'

Write-Host "`nОбновление пароля администратора..." -ForegroundColor Yellow

# SQL команда для обновления пароля
$sql = @"
UPDATE users 
SET password_hash = '$correctHash',
    updated_at = now()
WHERE username = 'admin' AND role = 'admin';

SELECT username, status, role, LENGTH(password_hash) as hash_length 
FROM users 
WHERE username = 'admin';
"@

$result = kubectl exec $postgresPod -- psql -U user -d 2fa -c $sql 2>&1

if ($LASTEXITCODE -eq 0 -and $result -match "UPDATE 1") {
    Write-Host "`n✅ Пароль администратора успешно обновлен!" -ForegroundColor Green
    Write-Host $result -ForegroundColor White
    Write-Host "`nУчетные данные:" -ForegroundColor Green
    Write-Host "  Username: admin" -ForegroundColor White
    Write-Host "  Password: admin123" -ForegroundColor White
} else {
    Write-Host "`n⚠ Проблема при обновлении. Попробуем создать заново..." -ForegroundColor Yellow
    
    # Удаление и создание заново
    kubectl exec $postgresPod -- psql -U user -d 2fa -c "DELETE FROM users WHERE username = 'admin';" | Out-Null
    
    $insertSql = @"
INSERT INTO users (id, username, email, password_hash, status, role, created_at, updated_at)
VALUES (
    uuid_generate_v4(),
    'admin',
    'admin@example.com',
    '$correctHash',
    'active',
    'admin',
    now(),
    now()
);
SELECT username, status, role FROM users WHERE username = 'admin';
"@
    
    $result = kubectl exec $postgresPod -- psql -U user -d 2fa -c $insertSql 2>&1
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "`n✅ Администратор успешно создан!" -ForegroundColor Green
        Write-Host $result -ForegroundColor White
    } else {
        Write-Host "`n❌ Ошибка создания администратора" -ForegroundColor Red
        Write-Host $result -ForegroundColor Red
    }
}

Write-Host "`nТеперь попробуйте войти с:" -ForegroundColor Green
Write-Host "  Username: admin" -ForegroundColor White
Write-Host "  Password: admin123" -ForegroundColor White
