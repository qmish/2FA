# Скрипты и утилиты

## Развертывание и запуск
- `deploy-k3d.ps1` / `deploy-k3d.sh` — полный деплой в K3D.
- `rebuild-images.ps1` — пересборка Docker образов.
- `install-k3d.ps1` — установка K3D на Windows.

## Доступ и домены
- `setup-domain.ps1` — настройка домена для UI.
- `setup-radius-domain.ps1` — настройка домена для RADIUS.

## UI
- `start-ui.ps1` — запуск UI через port-forward.
- `start-ui-permanent.ps1` — альтернативный запуск UI.
- `start-ui-fixed.ps1` — фиксированный запуск UI.

## Админ
- `create-admin.ps1` / `create-admin-direct.ps1` — создание администратора.
- `fix-admin-password.ps1` / `fix-admin-password-final.ps1` — исправление пароля администратора.
- `verify-admin-hash.ps1` — проверка bcrypt хеша.
- `test-admin-login.ps1` / `test-admin-login-full.ps1` — тесты логина.
- `fix-admin-login-complete.ps1` — комплексный фикс логина.
- `create-admin.sql` / `fix-admin-hash.sql` — SQL скрипты.

## VPN / RADIUS
- `create-vpn-user-api.ps1` / `create-vpn-user-sql.ps1` / `create-vpn-user-auto.ps1` — создание тестового VPN пользователя.
- `create-radius-client.ps1` — создание RADIUS клиента.
- `create-test-vpn-user.ps1` — тестовый VPN пользователь (упрощенный).
- `test-radius-anyconnect.ps1` — тест AnyConnect.

## Port-forward
- `port-forward.ps1` / `port-forward-all.ps1` — port-forward ко всем сервисам.

## Прочее
- `test-api.ps1` — базовые проверки API.
- `test-e2e.ps1` — E2E проверки (healthz/metrics/login).
- `k6-load.js` — нагрузочный тест (k6, BASE_URL).
- `generate-bcrypt-hash.go` — генерация bcrypt хеша.
- `go.mod` — зависимости скриптов.
