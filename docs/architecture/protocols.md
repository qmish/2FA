# Протоколы и форматы

## HTTP/JSON (API)
- REST endpoints: `/api/v1/*`
- Формат: JSON
- Авторизация: JWT access/refresh

## JWT
- Access token: короткий TTL
- Refresh token: rotation через `/auth/refresh`

## RADIUS
- Access-Request / Access-Accept / Access-Reject
- UDP/1812

## WebAuthn (Passkeys)
- Регистрация и логин через WebAuthn API
- Сессии WebAuthn сохраняются в PostgreSQL

## LDAP/AD
- Первый фактор может проверяться через LDAP

## Пример JSON (login)
```json
{
  "username": "user",
  "password": "password"
}
```
