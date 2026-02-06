# Как создать тестового пользователя для VPN

Есть несколько способов создать тестового пользователя для тестирования с Cisco AnyConnect.

## Способ 1: Через API (рекомендуется) ✅

Самый простой способ - использовать скрипт, который создаст пользователя через API.

### Шаг 1: Получите админский токен

1. Откройте UI: http://2fa.local/ui/ или http://localhost:30080/ui/
2. Войдите как admin:
   - Username: `admin`
   - Password: `admin123`
3. После входа скопируйте токен из поля **"Admin token"**

### Шаг 2: Запустите скрипт

```powershell
.\scripts\create-vpn-user-api.ps1
```

Скрипт попросит:
- Админский токен (вставьте скопированный токен)
- Username (по умолчанию: `vpnuser`)
- Password (по умолчанию: `test123`)
- Phone (по умолчанию: `+79991234567`)
- Email (необязательно)

Скрипт автоматически создаст пользователя через API.

## Способ 2: Через SQL напрямую

Если API недоступен или есть проблемы, можно создать пользователя напрямую через SQL:

```powershell
.\scripts\create-vpn-user-sql.ps1
```

Скрипт:
1. Генерирует хеш пароля автоматически
2. Создает пользователя в базе данных
3. Показывает результат

## Способ 3: Вручную через SQL

Если скрипты не работают, можно создать пользователя вручную:

### Шаг 1: Сгенерируйте хеш пароля

```powershell
docker run --rm python:3-alpine sh -c "pip install bcrypt && python -c 'import bcrypt; print(bcrypt.hashpw(b\"test123\", bcrypt.gensalt()).decode())'"
```

Скопируйте полученный хеш (начинается с `$2b$12$...`)

### Шаг 2: Создайте пользователя в базе

```powershell
$postgresPod = kubectl get pods -l app=postgres -o jsonpath='{.items[0].metadata.name}'
$hash = "<ВСТАВЬТЕ_ХЕШ_СЮДА>"

kubectl exec $postgresPod -- psql -U user -d 2fa -c @"
INSERT INTO users (id, username, status, role, password_hash, phone, created_at, updated_at)
VALUES (
    gen_random_uuid(),
    'vpnuser',
    'active',
    'user',
    '$hash',
    '+79991234567',
    NOW(),
    NOW()
)
ON CONFLICT (username) DO UPDATE
SET password_hash = '$hash',
    phone = '+79991234567',
    status = 'active',
    updated_at = NOW();
"@
```

## Способ 4: Через админку UI (если есть интерфейс)

Если в UI есть интерфейс для создания пользователей:

1. Откройте UI: http://2fa.local/ui/ или http://localhost:30080/ui/
2. Войдите как admin (admin/admin123)
3. Найдите раздел "Users" или "Пользователи"
4. Нажмите "Create" или "Создать"
5. Заполните форму:
   - Username: `vpnuser`
   - Password: `test123`
   - Phone: `+79991234567`
   - Status: `active`
   - Role: `user`

## Проверка создания пользователя

После создания проверьте, что пользователь создан:

```powershell
$postgresPod = kubectl get pods -l app=postgres -o jsonpath='{.items[0].metadata.name}'
kubectl exec $postgresPod -- psql -U user -d 2fa -c "SELECT username, status, phone FROM users WHERE username = 'vpnuser';"
```

Должно показать:
```
 username | status |    phone     
----------+--------+--------------
 vpnuser  | active | +79991234567
```

## Учетные данные для тестирования

После создания пользователя используйте:

- **Username:** `vpnuser`
- **Password:** `test123`
- **Phone:** `+79991234567` (для получения OTP)

## Что дальше?

После создания пользователя:

1. Запустите port-forward для RADIUS:
   ```bash
   kubectl port-forward svc/radius-server 1812:1812
   ```

2. Протестируйте подключение через Cisco AnyConnect или radclient

3. Проверьте логи:
   ```bash
   kubectl logs -l app=radius-server --tail=50
   ```

## Устранение проблем

### Ошибка "user_conflict"

Пользователь с таким username уже существует. Скрипт автоматически обновит существующего пользователя.

### Ошибка "invalid_phone"

Проверьте формат телефона. Должен быть в формате: `+79991234567` (с плюсом и кодом страны).

### Ошибка авторизации при использовании API

1. Проверьте, что токен правильный
2. Убедитесь, что вы вошли как admin
3. Проверьте, что port-forward запущен

### Не удается сгенерировать хеш

Используйте способ 1 (через API) - он не требует генерации хеша.
