# Статус RADIUS сервера и интеграции с Cisco AnyConnect

## Текущий статус

### ✅ Готово

1. **RADIUS сервер**
   - Поды запущены: 2 реплики
   - Статус: Running
   - Порт: 1812/UDP

2. **RADIUS Service**
   - Тип: ClusterIP
   - Порт: 1812/UDP
   - Протокол: UDP

3. **RADIUS клиент**
   - Имя: `cisco-anyconnect`
   - IP: `0.0.0.0/0` (принимает запросы с любого IP)
   - Секрет: `cisco123`
   - Статус: Enabled

### ⚠️ Требуется настройка

1. **Тестовый пользователь**
   - Нужно создать пользователя с телефоном для получения OTP
   - Рекомендуется создать через админку UI

2. **SMS провайдер** (опционально)
   - Для отправки OTP кодов
   - Настраивается через переменные окружения

## Быстрая проверка

```bash
# Поды RADIUS сервера
kubectl get pods -l app=radius-server

# Service
kubectl get svc radius-server

# RADIUS клиенты
kubectl exec <postgres-pod> -- psql -U user -d 2fa -c \
  "SELECT name, ip, enabled FROM radius_clients;"

# Пользователи с телефонами
kubectl exec <postgres-pod> -- psql -U user -d 2fa -c \
  "SELECT username, status, phone FROM users WHERE phone IS NOT NULL AND phone != '';"
```

## Следующие шаги

1. Создайте тестового пользователя через админку UI
2. Запустите port-forward для доступа к RADIUS серверу
3. Протестируйте подключение с помощью radclient или Cisco AnyConnect
4. Проверьте логи и историю входов

Подробные инструкции: `docs/CISCO_ANYCONNECT_QUICKSTART.md`
