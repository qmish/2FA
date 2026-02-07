# Продакшен‑рекомендации

## WebAuthn (passkeys)
- Требуется HTTPS и корректный домен.
- `webauthn_rp_id` должен соответствовать домену приложения (RP ID).
- `webauthn_rp_origin` должен быть HTTPS‑origin того же домена.
- `webauthn_rp_name` — отображаемое имя сервиса.
- Для локальной отладки допускается `http://localhost`/`http://127.0.0.1`, в проде — только HTTPS.
- Время на серверах должно быть синхронизировано (NTP), иначе возможны ошибки WebAuthn.

## CI/CD
- Сборка: `go build ./cmd/api-server` и `go build ./cmd/radius-server`.
- Миграции запускать как отдельный шаг (`cmd/migrate`) до выката новой версии API.
- Для Kubernetes используйте `RollingUpdate` и healthchecks (`/healthz`).
- Теги образов должны быть версионными (например, `v1.44.32`) для откатов.
- Перед релизом прогонять тесты: `go test ./...`.

## TLS/Ingress
- Для продакшна используйте HTTPS и TLS‑секреты (Ingress + cert‑manager).
- Пример Ingress с TLS: `docs/k8s/api-ingress.yaml`.
- В Helm включайте `ingress.enabled` и `ingress.tls.enabled`.

## Секреты
- Не храните реальные секреты в репозитории.
- Для Helm можно указать `secrets.existingSecret` и создать секрет отдельно.
- Для Kubernetes используйте внешние секрет‑менеджеры (External Secrets/Sealed Secrets/Vault).

## Надежность
- Рекомендуется использовать RollingUpdate и PodDisruptionBudget.
- Примеры PDB: `docs/k8s/api-pdb.yaml`, `docs/k8s/radius-pdb.yaml`.
- Настройте `resources` для CPU/Memory в Helm/манифестах.
- Для Redis используйте PersistentVolume вместо `emptyDir`.
- Для HA PostgreSQL используйте оператор (пример: `docs/k8s/postgres-cnpg.yaml`).

## Мониторинг
- Для Prometheus Operator используйте ServiceMonitor: `docs/k8s/api-servicemonitor.yaml`.
- В Helm включайте `monitoring.enabled` и задавайте namespace мониторинга.

## Логирование
- Для централизованного логирования можно использовать Loki/Promtail.
- Примеры манифестов: `docs/k8s/logging-loki.yaml`, `docs/k8s/logging-promtail.yaml`.

## Сеть
- Для изоляции компонентов используйте NetworkPolicy.
- Пример базовых правил: `docs/k8s/network-policies.yaml`.

## Доступы в Kubernetes
- Используйте отдельные ServiceAccount и минимальные RBAC права.
- Пример манифеста: `docs/k8s/rbac.yaml`.

## SecurityContext
- Запускайте контейнеры от non‑root пользователя.
- Примеры в `docs/k8s/api-deployment.yaml`, `docs/k8s/radius-deployment.yaml`.

## DR (Disaster Recovery)
- План восстановления и тесты: `docs/disaster-recovery.md`.

## Alertmanager
- Пример развёртывания Alertmanager: `docs/k8s/alertmanager.yaml`.

## Резервное копирование
- PostgreSQL: регулярные `pg_dump` с проверкой восстановления.
- Хранить бэкапы минимум N дней (настройте политику ретенции).
- Проверять восстановление на стенде (restore + `cmd/migrate`).
- Секреты и конфиги (JWT, RADIUS, FCM и др.) хранить вне репозитория и бэкапить отдельно.
- Пример CronJob и PVC: `docs/k8s/postgres-backup-cronjob.yaml`, `docs/k8s/postgres-backup-pvc.yaml`.
