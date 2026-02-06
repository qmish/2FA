# Скрипт для создания администратора напрямую в базе данных

$ErrorActionPreference = "Stop"

Write-Host "=== Создание администратора в базе данных ===" -ForegroundColor Cyan

# Проверка наличия PostgreSQL
$postgresPod = kubectl get pods -l app=postgres -o jsonpath='{.items[0].metadata.name}'
if (-not $postgresPod) {
    Write-Host "Ошибка: PostgreSQL не запущен!" -ForegroundColor Red
    exit 1
}

Write-Host "`nPostgreSQL найден: $postgresPod" -ForegroundColor Green

# Запрос данных
Write-Host "`nВведите данные администратора:" -ForegroundColor Yellow
$username = Read-Host "Username (по умолчанию: admin)"
if ([string]::IsNullOrWhiteSpace($username)) {
    $username = "admin"
}

$password = Read-Host "Password (по умолчанию: admin123)" -AsSecureString
$passwordPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($password))
if ([string]::IsNullOrWhiteSpace($passwordPlain)) {
    $passwordPlain = "admin123"
}

$email = Read-Host "Email (по умолчанию: admin@example.com)"
if ([string]::IsNullOrWhiteSpace($email)) {
    $email = "admin@example.com"
}

Write-Host "`nСоздание администратора..." -ForegroundColor Yellow
Write-Host "Username: $username" -ForegroundColor White
Write-Host "Email: $email" -ForegroundColor White

# Генерация хеша пароля (используем Python для генерации bcrypt хеша)
$pythonScript = @"
import bcrypt
password = '$passwordPlain'
hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
print(hash.decode('utf-8'))
"@

try {
    $hash = python -c $pythonScript 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "`n⚠ Python не найден. Используем предустановленный хеш для 'admin123'" -ForegroundColor Yellow
        $hash = '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy'
        if ($passwordPlain -ne "admin123") {
            Write-Host "Для другого пароля установите Python или используйте онлайн генератор bcrypt" -ForegroundColor Yellow
        }
    }
} catch {
    Write-Host "⚠ Ошибка генерации хеша. Используем предустановленный хеш" -ForegroundColor Yellow
    $hash = '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy'
}

# SQL команда
$sql = @"
INSERT INTO users (id, username, email, password_hash, status, role, created_at, updated_at)
VALUES (
    uuid_generate_v4(),
    '$username',
    '$email',
    '$hash',
    'active',
    'admin',
    now(),
    now()
)
ON CONFLICT (username) DO UPDATE SET
    password_hash = EXCLUDED.password_hash,
    email = EXCLUDED.email,
    status = EXCLUDED.status,
    role = EXCLUDED.role,
    updated_at = now();
SELECT id, username, email, status, role, created_at FROM users WHERE username = '$username';
"@

Write-Host "`nВыполнение SQL команды..." -ForegroundColor Yellow

# Выполнение SQL через kubectl exec
$result = kubectl exec $postgresPod -- psql -U user -d 2fa -c $sql

if ($LASTEXITCODE -eq 0) {
    Write-Host "`n✅ Администратор успешно создан!" -ForegroundColor Green
    Write-Host $result -ForegroundColor White
    Write-Host "`nТеперь вы можете войти в админку:" -ForegroundColor Green
    Write-Host "  Username: $username" -ForegroundColor White
    Write-Host "  Password: $passwordPlain" -ForegroundColor White
} else {
    Write-Host "`n❌ Ошибка создания администратора" -ForegroundColor Red
    Write-Host $result -ForegroundColor Red
}
