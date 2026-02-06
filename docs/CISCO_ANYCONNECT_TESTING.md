# Тестирование с Cisco AnyConnect

## Обзор

Данное руководство описывает процесс тестирования интеграции приложения с Cisco AnyConnect VPN клиентом через RADIUS протокол.

## Архитектура

```
Cisco AnyConnect Client
    ↓ (RADIUS PAP)
RADIUS Server (UDP 31812)
    ↓
2FA Authentication Service
    ↓
PostgreSQL Database
```

## Требования

1. ✅ RADIUS сервер запущен и работает
2. ✅ Тестовый пользователь создан с телефоном
3. ✅ RADIUS клиент настроен в базе данных
4. ✅ Service для RADIUS создан

## Настройка

### 1. Проверка RADIUS сервера

```bash
kubectl get pods -l app=radius-server
kubectl get svc radius-server
```

### 2. Создание тестового пользователя

Используйте скрипт:
```powershell
.\scripts\create-test-vpn-user.ps1
```

Или создайте вручную через SQL:
```sql
-- Хеш пароля для "test123"
INSERT INTO users (id, username, status, role, password_hash, phone, created_at, updated_at)
VALUES (
    gen_random_uuid(),
    'vpnuser',
    'active',
    'user',
    '$2b$12$...',  -- Сгенерируйте через Python/Docker
    '+79991234567',
    NOW(),
    NOW()
);
```

### 3. Создание RADIUS клиента

Используйте скрипт:
```powershell
.\scripts\create-radius-client.ps1
```

Или создайте через SQL:
```sql
INSERT INTO radius_clients (id, name, ip, secret, enabled, created_at)
VALUES (
    gen_random_uuid(),
    'cisco-anyconnect',
    '0.0.0.0/0',  -- Принимаем с любого IP
    'cisco123',   -- Секрет для Cisco AnyConnect
    true,
    NOW()
);
```

## Процесс аутентификации

### Формат пароля для 2FA

RADIUS сервер поддерживает двухфакторную аутентификацию через формат:
```
<password>:<otp_code>
```

### Шаг 1: Первый запрос (только пароль)

**Запрос:**
- Username: `vpnuser`
- Password: `test123`

**Ответ:**
- Code: `Access-Reject`
- Message: `otp_required`
- Действие: Сервер отправляет OTP код на телефон пользователя

### Шаг 2: Второй запрос (пароль + OTP)

**Запрос:**
- Username: `vpnuser`
- Password: `test123:123456` (где 123456 - OTP код)

**Ответ:**
- Code: `Access-Accept` (при правильном OTP)
- Code: `Access-Reject` (при неправильном OTP)

## Тестирование

### Вариант 1: Использование radclient

1. Установите FreeRADIUS utils:
   ```bash
   # Ubuntu/Debian
   sudo apt-get install freeradius-utils
   
   # Windows (через Chocolatey)
   choco install freeradius
   ```

2. Используйте домен RADIUS:
   ```bash
   radius.2fa.local:31812
   ```

3. Создайте файл `radius-test.txt`:
   ```
   User-Name = vpnuser
   User-Password = test123
   NAS-IP-Address = 127.0.0.1
   ```

4. Отправьте запрос:
   ```bash
   radclient -x radius.2fa.local:31812 auth cisco123 < radius-test.txt
   ```

### Вариант 2: Использование Docker

```bash
# В другом терминале
docker run --rm -it --network host freeradius/freeradius-server:latest \
  radclient -x radius.2fa.local:31812 auth cisco123 < radius-test.txt
```

### Вариант 3: Настройка Cisco AnyConnect

1. **Откройте Cisco AnyConnect Secure Mobility Client**

2. **Добавьте сервер:**
   - Server: `radius.2fa.local:31812` (или `<K3D_NODE_IP>:31812`)

3. **Настройте аутентификацию:**
   - Authentication: RADIUS
   - RADIUS Server: `radius.2fa.local:31812` (или `<K3D_NODE_IP>:31812`)
   - Secret: `cisco123`
   - Protocol: PAP (Password Authentication Protocol)

4. **Подключение:**
   - Username: `vpnuser`
   - Password: `test123` (первый запрос)
   - После получения OTP: `test123:123456`

## Проверка логов

### Логи RADIUS сервера

```bash
kubectl logs -l app=radius-server --tail=50
```

### История входов

```bash
kubectl exec <postgres-pod> -- psql -U user -d 2fa -c \
  "SELECT username, result, created_at FROM login_history WHERE channel = 'vpn' ORDER BY created_at DESC LIMIT 10;"
```

### RADIUS запросы

```bash
kubectl exec <postgres-pod> -- psql -U user -d 2fa -c \
  "SELECT username, result, created_at FROM radius_requests ORDER BY created_at DESC LIMIT 10;"
```

## Устранение проблем

### Проблема: Access-Reject при правильном пароле

**Причины:**
1. Пользователь не активен
2. Неправильный хеш пароля
3. RADIUS клиент не настроен или отключен
4. Неправильный секрет

**Решение:**
1. Проверьте статус пользователя:
   ```sql
   SELECT username, status FROM users WHERE username = 'vpnuser';
   ```

2. Проверьте RADIUS клиента:
   ```sql
   SELECT name, ip, enabled FROM radius_clients;
   ```

3. Проверьте секрет в конфигурации:
   ```bash
   kubectl get configmap api-config -o jsonpath='{.data.RADIUS_SECRET}'
   ```

### Проблема: OTP не отправляется

**Причины:**
1. У пользователя нет телефона
2. SMS провайдер не настроен
3. Неправильный формат телефона

**Решение:**
1. Проверьте телефон пользователя:
   ```sql
   SELECT username, phone FROM users WHERE username = 'vpnuser';
   ```

2. Проверьте конфигурацию SMS провайдера:
   ```bash
   kubectl get configmap api-config -o jsonpath='{.data.EXPRESS_MOBILE_URL}'
   kubectl get secret api-secrets -o jsonpath='{.data.EXPRESS_MOBILE_KEY}'
   ```

### Проблема: Не удается подключиться к RADIUS серверу

**Причины:**
1. Service не создан
2. Домен не резолвится в `<K3D_NODE_IP>`
3. Firewall блокирует UDP 31812

**Решение:**
1. Создайте Service:
   ```bash
   kubectl apply -f docs/k8s/radius-service.yaml
   ```

2. Убедитесь, что домен резолвится:
   ```bash
   nslookup radius.2fa.local
   ```

3. Проверьте доступность:
   ```bash
   kubectl get svc radius-server
   ```

## Конфигурация для production

Для production окружения:

1. **Ограничьте IP адреса RADIUS клиентов:**
   ```sql
   UPDATE radius_clients SET ip = '<CISCO_ASA_IP>/32' WHERE name = 'cisco-anyconnect';
   ```

2. **Используйте сильный секрет:**
   ```sql
   UPDATE radius_clients SET secret = '<STRONG_SECRET>' WHERE name = 'cisco-anyconnect';
   ```

3. **Настройте NodePort или LoadBalancer для внешнего доступа:**
   ```yaml
   apiVersion: v1
   kind: Service
   metadata:
     name: radius-server
   spec:
     type: NodePort
     ports:
       - port: 1812
         targetPort: 1812
         nodePort: 31812
         protocol: UDP
   ```

## Дополнительные ресурсы

- [RADIUS Protocol RFC 2865](https://tools.ietf.org/html/rfc2865)
- [Cisco AnyConnect Documentation](https://www.cisco.com/c/en/us/support/security/anyconnect-secure-mobility-client/products-user-guide-list.html)
- [FreeRADIUS Documentation](https://freeradius.org/documentation/)
