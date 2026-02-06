# Исправление ошибки admin_login_failed

## Проблема

При попытке входа в админку возникает ошибка:
```json
{
  "status": 401,
  "payload": {
    "error": "admin_login_failed"
  }
}
```

## Причина

Ошибка может возникать по нескольким причинам:

1. **Неправильный хеш пароля в базе данных** - хеш был сохранен некорректно
2. **Пользователь не найден** - администратор не создан или имеет неправильную роль
3. **Неверный статус пользователя** - статус не равен 'active'
4. **Неправильный пароль** - введен неверный пароль

## Решение

### Автоматическое исправление

Используйте готовый скрипт:

```powershell
.\scripts\fix-admin-password.ps1
```

Скрипт автоматически:
- Проверит существование администратора
- Обновит хеш пароля на правильный
- Проверит результат

### Ручное исправление

1. Подключитесь к базе данных:
```powershell
$postgresPod = kubectl get pods -l app=postgres -o jsonpath='{.items[0].metadata.name}'
kubectl exec -it $postgresPod -- psql -U user -d 2fa
```

2. Проверьте текущего администратора:
```sql
SELECT username, status, role, LENGTH(password_hash) as hash_length 
FROM users 
WHERE username = 'admin';
```

3. Если хеш неправильный (длина не 60 символов), обновите:
```sql
-- Хеш для пароля "admin123"
UPDATE users 
SET password_hash = '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy',
    updated_at = now()
WHERE username = 'admin' AND role = 'admin';
```

4. Или удалите и создайте заново:
```sql
DELETE FROM users WHERE username = 'admin';

INSERT INTO users (id, username, email, password_hash, status, role, created_at, updated_at)
VALUES (
    uuid_generate_v4(),
    'admin',
    'admin@example.com',
    '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy',
    'active',
    'admin',
    now(),
    now()
);
```

## Проверка

После исправления проверьте вход:

```powershell
$body = @{
    username = "admin"
    password = "admin123"
} | ConvertTo-Json

$response = Invoke-RestMethod -Uri "http://localhost:8083/api/v1/admin/auth/login" `
    -Method POST `
    -Body $body `
    -ContentType "application/json"

Write-Host "Token: $($response.access_token)"
```

## Правильные учетные данные

После исправления используйте:

- **Username**: `admin`
- **Password**: `admin123`
- **Email**: `admin@example.com`
- **Role**: `admin`
- **Status**: `active`

## Диагностика

Если проблема сохраняется, проверьте:

1. **Статус пользователя**:
```sql
SELECT username, status, role FROM users WHERE username = 'admin';
```
Должно быть: `status = 'active'`, `role = 'admin'`

2. **Длина хеша пароля**:
```sql
SELECT LENGTH(password_hash) FROM users WHERE username = 'admin';
```
Должно быть: `60` символов

3. **Начало хеша**:
```sql
SELECT LEFT(password_hash, 7) FROM users WHERE username = 'admin';
```
Должно быть: `$2a$10$`

4. **Логи API сервера**:
```powershell
kubectl logs -l app=api-server --tail=50 | Select-String -Pattern "admin|login"
```

## Генерация нового хеша пароля

Если нужно использовать другой пароль:

### Используя Python:
```python
import bcrypt
password = "your_password"
hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
print(hash.decode('utf-8'))
```

### Используя онлайн генератор:
- https://bcrypt-generator.com/
- https://www.bcrypt.fr/

## Предотвращение проблемы

Чтобы избежать проблемы в будущем:

1. Используйте скрипт `scripts/create-admin-direct.ps1` для создания администратора
2. Проверяйте длину хеша после создания (должно быть 60 символов)
3. Используйте правильное экранирование при работе с SQL
