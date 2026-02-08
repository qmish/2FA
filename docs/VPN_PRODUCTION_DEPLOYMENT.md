# Продакшен‑гайд: VPN (Cisco AnyConnect)

## Цель
Организовать 2FA для пользователей корпоративной сети при авторизации через VPN (Cisco AnyConnect) с использованием RADIUS.

## Предусловия
- Развёрнуты API и RADIUS сервисы.
- Настроены секреты `RADIUS_SECRET`, `DB_URL`, `REDIS_URL`.
- DNS и сеть позволяют ASA/FTD обращаться к RADIUS.

## Схема доступа
1. ASA/FTD отправляет RADIUS Access‑Request на RADIUS сервер.
2. RADIUS сервер проверяет логин/пароль и инициирует 2FA.
3. Пользователь подтверждает код/Push/Call.
4. RADIUS возвращает Access‑Accept/Reject.

## Сетевые требования
- UDP порт 1812 доступен с ASA/FTD до RADIUS.
- Для прод‑доменов используйте реальный DNS (не `*.local`).
- При балансировке UDP используйте L4 LoadBalancer/ExternalIP.

## Конфигурация RADIUS
- Укажите `RADIUS_SECRET` и `RADIUS_ADDR`.
- Проверьте `radius_requests_total` и логи при попытках логина.

## Cisco ASA/FTD (кратко)
- Добавить AAA Server Group типа RADIUS.
- Указать RADIUS сервер(ы) и общий секрет.
- Привязать AAA к VPN (AnyConnect).
- Проверить тестовую авторизацию.

## Проверки после внедрения
- `radius_requests_total` растёт при логинах.
- `auth_logins_total` и `auth_challenges_total` без всплесков ошибок.
- Нет ошибок `system_errors_total{component="db|redis"}`.

## Диагностика
- Если отказы: проверить `RADIUS_SECRET`, сеть, доступность UDP.
- Проверить `redis_ping_total`, `db_ping_total`.
- Проверить каналы доставки (SMS/Push/Call).
