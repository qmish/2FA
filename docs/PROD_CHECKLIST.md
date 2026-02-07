# Чек‑лист прод‑готовности

## P0 (критично)
- [x] TLS/HTTPS для Ingress (cert‑manager/Let’s Encrypt, TLS‑секреты).
- [x] Секреты без `CHANGE_ME`, поддержка внешнего secret‑менеджера.
- [x] Бэкапы PostgreSQL (CronJob `pg_dump`/оператор).
- [x] CI/CD: миграции как отдельный шаг, сборка образов по тегам.
- [x] Версионирование образов (теги `vX.Y.Z`).

## P1 (важно)
- [x] PV для Redis вместо `emptyDir`.
- [x] Resources requests/limits для подов.
- [x] Мониторинг: ServiceMonitor для `/metrics`.
- [x] RollingUpdate + PodDisruptionBudget.
- [x] Централизованное логирование (Loki/ELK/Cloud).
- [x] HA PostgreSQL (оператор/репликация).

## P2 (желательно)
- [x] NetworkPolicy для изоляции компонентов.
- [x] RBAC/ServiceAccount с минимальными правами.
- [x] SecurityContext (`runAsNonRoot`, `runAsUser`).
- [ ] DR‑план с процедурами восстановления.
- [ ] Alertmanager и интеграции.
- [ ] SSL для PostgreSQL (`sslmode=disable` заменить).
- [ ] Ingress rate‑limit на уровне ingress.
- [ ] Прод‑домены WebAuthn в гайдах (без `2fa.local`).
