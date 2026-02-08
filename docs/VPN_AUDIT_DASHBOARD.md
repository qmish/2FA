# Дашборд аудита VPN‑сессий и подключений

Цель: контроль активности VPN‑логинов, успешности 2FA и аномалий.

## Основные панели (PromQL)

### 1) Успешные/ошибочные логины (RPS)
```
sum by (result) (rate(auth_logins_total[5m]))
```

### 2) Доля ошибок логина (%)
```
100 * sum(rate(auth_logins_total{result="failed"}[5m])) /
sum(rate(auth_logins_total[5m]))
```

### 3) Регистрации (RPS)
```
sum by (result) (rate(auth_registrations_total[5m]))
```

### 4) 2FA события (passkey/OTP)
```
sum by (operation, result) (rate(passkey_events_total[5m]))
```

### 5) Блокировки
```
sum(rate(lockout_created_total[5m]))
```
```
sum(lockout_active_total)
```

### 6) Сессии (операции)
```
sum by (operation, result) (rate(sessions_total[5m]))
```

## Рекомендованные пороги
- Ошибки логина > 5% в течение 10–15 минут — проверить провайдеры и RADIUS.
- Рост блокировок — проверить атаки перебора.
- Снижение успешных логинов — проверить сеть/ASA/FTD.

## Источники
- Метрики: `GET /metrics`
- Документация метрик: `docs/observability.md`
