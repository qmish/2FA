# Автоматический скрипт для создания VPN пользователя (без интерактивного ввода)

Write-Host "`n=== АВТОМАТИЧЕСКОЕ СОЗДАНИЕ VPN ПОЛЬЗОВАТЕЛЯ ===" -ForegroundColor Cyan

$postgresPod = kubectl get pods -l app=postgres -o jsonpath='{.items[0].metadata.name}' 2>&1
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($postgresPod)) {
    Write-Host "❌ Не удалось найти под PostgreSQL" -ForegroundColor Red
    exit 1
}

Write-Host "Под PostgreSQL: $postgresPod" -ForegroundColor Green

# Параметры по умолчанию
$username = "vpnuser"
$password = "test123"
$phone = "+79991234567"

Write-Host "`nПараметры пользователя:" -ForegroundColor Yellow
Write-Host "  Username: $username" -ForegroundColor White
Write-Host "  Password: $password" -ForegroundColor White
Write-Host "  Phone: $phone" -ForegroundColor White

# Генерируем хеш пароля
Write-Host "`nГенерирую хеш пароля..." -ForegroundColor Yellow

# Создаем временный Python файл для генерации хеша
$tempPyFile = "temp_bcrypt_gen.py"
@"
import bcrypt
password = b"$password"
hash = bcrypt.hashpw(password, bcrypt.gensalt())
print(hash.decode())
"@ | Out-File -FilePath $tempPyFile -Encoding utf8

try {
    $hashOutput = docker run --rm -v "${PWD}:/app" -w /app python:3-alpine sh -c "pip install bcrypt > /dev/null 2>&1 && python /app/$tempPyFile" 2>&1
    
    # Удаляем временный файл
    Remove-Item $tempPyFile -ErrorAction SilentlyContinue
    
    # Извлекаем хеш
    $hash = $null
    foreach ($line in $hashOutput) {
        if ($line -match '\$2[ab]\$[0-9]+\$[A-Za-z0-9\./]+') {
            $hash = $line.Trim()
            break
        }
    }
    
    if ([string]::IsNullOrWhiteSpace($hash)) {
        Write-Host "❌ Не удалось сгенерировать хеш пароля" -ForegroundColor Red
        Write-Host "Вывод: $hashOutput" -ForegroundColor Yellow
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
        
        Write-Host "`n✅ Теперь можно тестировать подключение через Cisco AnyConnect!" -ForegroundColor Green
    } else {
        Write-Host "`n❌ Ошибка создания пользователя: $result" -ForegroundColor Red
        exit 1
    }
    
} catch {
    Write-Host "`n❌ Ошибка: $($_.Exception.Message)" -ForegroundColor Red
    Remove-Item $tempPyFile -ErrorAction SilentlyContinue
    exit 1
}

Write-Host "`n=== ГОТОВО ===" -ForegroundColor Green
