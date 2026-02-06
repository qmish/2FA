## Безопасность

### Lockout policy
- Блокировка при превышении `MaxAttemptsPerWindow` за `AttemptsWindowSeconds`.
- Запись блокировки в таблицу `lockouts`.
- Автоматическая очистка истекших блокировок.
- Админские эндпоинты: `/api/v1/admin/lockouts*`.
- Пользовательский статус: `/api/v1/lockouts/current`.
- Фильтры: `reason`, `active_only`.

### Аудит
- Запись событий входа и отказов в `audit_events`.
- История логинов хранится в `login_history`.
- Отзыв сессий (`session_revoke`, `session_revoke_all`) фиксируется в `audit_events`.
- Админские операции отзыва сессий пишутся с `actor_user_id` администратора.
- Для отзыва сессий сохраняется IP клиента.
- Выход пользователя (`logout`) фиксируется как `audit_events` для `session`.
- Обновление токена (`refresh`) фиксируется как `audit_events` для `session`.
- Для `logout` и `refresh` сохраняется IP клиента из запроса.
- Подтверждение 2FA фиксируется как `second_factor_approve`/`second_factor_deny` для `challenge`.
- Создание блокировки фиксируется как `lockout_create` для `lockout`.
- Очистка блокировок фиксируется как `lockout_clear` для `lockout`.
- Фильтры аудита: `actor_user_id`, `entity_type`, `action`, `entity_id`, `ip`, `payload`, `from`, `to`.
- В `payload` для 2FA хранится метод (`otp`/`call`/`push`), для `lockout_create` — причина.
