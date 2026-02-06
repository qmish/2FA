# Доступ к админке

## ⚠️ Важно: Дефолтного администратора нет!

В системе **нет** предустановленного администратора. Нужно создать первого администратора вручную.

## Способы создания администратора

### Способ 1: Через SQL (рекомендуется для первого запуска)

#### Вариант A: Использовать готовый скрипт

```powershell
.\scripts\create-admin-direct.ps1
```

Скрипт запросит:
- Username (по умолчанию: `admin`)
- Password (по умолчанию: `admin123`)
- Email (по умолчанию: `admin@example.com`)

#### Вариант B: Выполнить SQL вручную

1. Подключитесь к базе данных:
```powershell
$postgresPod = kubectl get pods -l app=postgres -o jsonpath='{.items[0].metadata.name}'
kubectl exec -it $postgresPod -- psql -U user -d 2fa
```

2. Выполните SQL:
```sql
-- Пароль: admin123
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
)
ON CONFLICT (username) DO NOTHING;
```

3. Проверьте создание:
```sql
SELECT id, username, email, status, role FROM users WHERE role = 'admin';
```

### Способ 2: Через API (требует существующего администратора)

Если у вас уже есть администратор, можно создать нового через API:

```powershell
# Убедитесь, что port-forward запущен
kubectl port-forward pod/<api-pod-name> 8083:8080

# Получите токен администратора (через UI или API)
$adminToken = "YOUR_ADMIN_TOKEN"

# Создайте нового администратора
$body = @{
    username = "newadmin"
    password = "password123"
    email = "newadmin@example.com"
    role = "admin"
    status = "active"
} | ConvertTo-Json

Invoke-RestMethod -Uri "http://localhost:8083/api/v1/admin/users/create" `
    -Method POST `
    -Body $body `
    -ContentType "application/json" `
    -Headers @{
        "Authorization" = "Bearer $adminToken"
    }
```

## Вход в админку

### Через UI

1. Откройте UI: http://localhost:8083/ui/
2. Перейдите в раздел "Admin login"
3. Введите:
   - **Username**: `admin` (или созданный вами)
   - **Password**: `admin123` (или созданный вами)
4. Нажмите "Admin login"
5. Скопируйте полученный токен
6. Используйте токен для административных операций

### Через API

```powershell
$body = @{
    username = "admin"
    password = "admin123"
} | ConvertTo-Json

$response = Invoke-RestMethod -Uri "http://localhost:8083/api/v1/admin/auth/login" `
    -Method POST `
    -Body $body `
    -ContentType "application/json"

# Токен будет в $response.access_token
$adminToken = $response.access_token
```

## Дефолтные учетные данные (после создания через SQL)

После выполнения SQL скрипта `scripts/create-admin.sql`:

- **Username**: `admin`
- **Password**: `admin123`
- **Email**: `admin@example.com`
- **Role**: `admin`
- **Status**: `active`

⚠️ **Важно**: Смените пароль после первого входа!

## Генерация хеша пароля

Если нужно создать администратора с другим паролем:

### Используя Python:

```python
import bcrypt
password = "your_password"
hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
print(hash.decode('utf-8'))
```

### Используя онлайн генератор:

Используйте любой онлайн генератор bcrypt, например:
- https://bcrypt-generator.com/
- https://www.bcrypt.fr/

## Проверка существующих администраторов

```powershell
$postgresPod = kubectl get pods -l app=postgres -o jsonpath='{.items[0].metadata.name}'
kubectl exec $postgresPod -- psql -U user -d 2fa -c "SELECT username, email, status, role FROM users WHERE role = 'admin';"
```

## Устранение проблем

### Ошибка "invalid credentials"

1. Проверьте, что пользователь существует:
```sql
SELECT username, status, role FROM users WHERE username = 'admin';
```

2. Проверьте, что статус = 'active' и роль = 'admin'

3. Проверьте правильность пароля

### Ошибка при создании через API

Если создание через API не работает (требует токен администратора), используйте SQL способ для создания первого администратора.

## Безопасность

⚠️ **Для production:**

1. Смените дефолтный пароль `admin123`
2. Используйте сложный пароль
3. Настройте ограничение доступа к админке
4. Используйте HTTPS/TLS
5. Регулярно проверяйте список администраторов
