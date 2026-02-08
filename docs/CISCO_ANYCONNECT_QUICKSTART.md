# Быстрый старт: Тестирование с Cisco AnyConnect

## Текущий статус

✅ RADIUS сервер запущен (2 пода)  
✅ RADIUS Service создан  
✅ RADIUS клиент создан (cisco-anyconnect)  
⚠️ Тестовый пользователь нужно создать вручную

## Быстрая настройка

### 1. Создание тестового пользователя

**Вариант A: Через админку UI**

1. Откройте UI: http://2fa.local/ui/ или http://localhost:30080/ui/
2. Войдите как admin (admin/admin123)
3. Перейдите в раздел управления пользователями
4. Создайте пользователя:
   - Username: `vpnuser`
   - Password: `test123`
   - Phone: `+79991234567` (или любой другой номер)
   - Status: `active`

**Вариант B: Через SQL**

```sql
-- Сначала сгенерируйте хеш пароля через Python/Docker
-- docker run --rm python:3-alpine sh -c "pip install bcrypt && python -c 'import bcrypt; print(bcrypt.hashpw(b\"test123\", bcrypt.gensalt()).decode())'"

-- Затем вставьте полученный хеш в запрос:
INSERT INTO users (id, username, status, role, password_hash, phone, created_at, updated_at)
VALUES (
    gen_random_uuid(),
    'vpnuser',
    'active',
    'user',
    '<ВСТАВЬТЕ_ХЕШ_СЮДА>',
    '+79991234567',
    NOW(),
    NOW()
);
```

### 2. Доступ к RADIUS без port-forward

RADIUS опубликован как **NodePort UDP 31812**.  
Используйте домен `radius.2fa.local:31812`.

Подробная настройка домена: `docs/RADIUS_DOMAIN_ACCESS.md`.

### 3. Тестирование подключения

#### Использование radclient

1. Установите FreeRADIUS utils (если еще не установлено)

2. Создайте файл `radius-test.txt`:
   ```
   User-Name = vpnuser
   User-Password = test123
   NAS-IP-Address = 127.0.0.1
   ```

3. Отправьте запрос:
   ```bash
   radclient -x radius.2fa.local:31812 auth cisco123 < radius-test.txt
   ```

**Ожидаемый результат:**
- Первый запрос: `Access-Reject` с сообщением `otp_required`
- После получения OTP на телефон: второй запрос с `test123:123456` → `Access-Accept`

> Важно: passkeys/WebAuthn не поддерживаются в RADIUS/AnyConnect. Используйте OTP/push/call.

#### Использование Docker (если radclient не установлен)

```bash
# Создайте файл radius-test.txt (см. выше)

docker run --rm -i --network host \
  -v $(pwd)/radius-test.txt:/test.txt \
  freeradius/freeradius-server:latest \
  radclient -x radius.2fa.local:31812 auth cisco123 < /test.txt
```

### 4. Настройка Cisco AnyConnect

1. **Откройте Cisco AnyConnect Secure Mobility Client**

2. **Добавьте сервер:**
   - Нажмите на значок шестеренки
   - Добавьте новый сервер: `radius.2fa.local` (или `<K3D_NODE_IP>`)

3. **Настройте RADIUS аутентификацию:**
   - Server: `radius.2fa.local:31812` (или `<K3D_NODE_IP>:31812`)
   - Authentication: RADIUS
   - Secret: `cisco123`
   - Protocol: PAP

4. **Подключение:**
   - Username: `vpnuser`
   - Password (первый раз): `test123`
   - После получения OTP: `test123:123456` (где 123456 - код из SMS)

## Создание тестового пользователя

Кратко:
- Через API скрипт: `scripts/create-vpn-user-api.ps1`
- Через SQL скрипт: `scripts/create-vpn-user-sql.ps1`

Подробно: `docs/CREATE_VPN_USER.md`

## Проверка работы

### Логи RADIUS сервера

```bash
kubectl logs -l app=radius-server --tail=50 -f
```

### История входов

```bash
kubectl exec <postgres-pod> -- psql -U user -d 2fa -c \
  "SELECT username, result, created_at FROM login_history WHERE channel = 'vpn' ORDER BY created_at DESC LIMIT 10;"
```

### Статус ресурсов

```bash
# Поды
kubectl get pods -l app=radius-server

# Service
kubectl get svc radius-server

# Пользователи
kubectl exec <postgres-pod> -- psql -U user -d 2fa -c \
  "SELECT username, status, phone FROM users WHERE username = 'vpnuser';"

# RADIUS клиенты
kubectl exec <postgres-pod> -- psql -U user -d 2fa -c \
  "SELECT name, ip, enabled FROM radius_clients;"
```

## Параметры подключения

- **RADIUS Server:** `radius.2fa.local:31812` (NodePort UDP) или `<K3D_NODE_IP>:31812`
- **Secret:** `cisco123`
- **Protocol:** PAP (Password Authentication Protocol)
- **Username:** `vpnuser`
- **Password:** `test123` (первый запрос), затем `test123:123456` (с OTP)

## Устранение проблем

### Access-Reject при правильном пароле

1. Проверьте статус пользователя:
   ```sql
   SELECT username, status FROM users WHERE username = 'vpnuser';
   ```
   Должно быть: `status = 'active'`

2. Проверьте RADIUS клиента:
   ```sql
   SELECT name, ip, enabled FROM radius_clients WHERE name = 'cisco-anyconnect';
   ```
   Должно быть: `enabled = true`

3. Проверьте секрет:
   ```bash
   kubectl get configmap api-config -o jsonpath='{.data.RADIUS_SECRET}'
   ```
   Должно совпадать с секретом в запросе (`cisco123`)

### OTP не отправляется

1. Проверьте телефон пользователя:
   ```sql
   SELECT username, phone FROM users WHERE username = 'vpnuser';
   ```

2. Проверьте конфигурацию SMS провайдера:
   ```bash
   kubectl get configmap api-config -o jsonpath='{.data.EXPRESS_MOBILE_URL}'
   ```

### Не удается подключиться

1. Убедитесь, что port-forward запущен:
   ```bash
   kubectl port-forward svc/radius-server 1812:1812
   ```

2. Проверьте доступность порта:
   ```bash
   Test-NetConnection -ComputerName localhost -Port 1812
   ```

## Дополнительная информация
- Статус RADIUS: `docs/RADIUS_STATUS.md`
