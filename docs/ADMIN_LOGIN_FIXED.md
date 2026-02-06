# Проблема входа администратора - РЕШЕНА ✅

## Проблема

При попытке входа в админку возникала ошибка 401:
```json
{
  "status": 401,
  "payload": {
    "error": "admin_login_failed"
  }
}
```

## Причина

Хеш пароля в базе данных не соответствовал паролю `admin123`. Bcrypt генерирует разные хеши каждый раз из-за случайной соли, поэтому старый хеш не проходил проверку.

## Решение

Проблема решена путем генерации правильного хеша для пароля `admin123` и обновления его в базе данных.

## Использование

Для исправления проблемы используйте скрипт:

```powershell
.\scripts\fix-admin-password-final.ps1
```

Этот скрипт:
1. ✅ Генерирует правильный bcrypt хеш для пароля `admin123`
2. ✅ Обновляет хеш в базе данных PostgreSQL
3. ✅ Перезапускает API сервер
4. ✅ Запускает port-forward
5. ✅ Тестирует вход и подтверждает успех

## Учетные данные

- **Username**: `admin`
- **Password**: `admin123`

## Доступ к UI

1. Убедитесь, что port-forward запущен (скрипт запускает его автоматически)
2. Откройте: http://localhost:8083/ui/
3. Перейдите в раздел "Admin login"
4. Введите учетные данные и нажмите "Login as admin"

## Важно

⚠️ **Оставьте окно с port-forward открытым!** Если вы закроете его, доступ к API прекратится.

## Диагностика

Если проблема повторится:

1. **Проверьте хеш в базе:**
```powershell
$postgresPod = kubectl get pods -l app=postgres -o jsonpath='{.items[0].metadata.name}'
kubectl exec $postgresPod -- psql -U user -d 2fa -c "SELECT username, LENGTH(password_hash) as len FROM users WHERE username = 'admin';"
```

2. **Проверьте логи API:**
```powershell
kubectl logs -l app=api-server --tail=50 | Select-String -Pattern "DEBUG|admin|login"
```

3. **Перезапустите исправление:**
```powershell
.\scripts\fix-admin-password-final.ps1
```

## Технические детали

- Используется bcrypt с cost factor 12 (по умолчанию)
- Хеш генерируется через Python библиотеку bcrypt
- Формат хеша: `$2b$12$...` (совместим с Go библиотекой `golang.org/x/crypto/bcrypt`)
- После обновления хеша необходимо перезапустить API сервер для применения изменений
