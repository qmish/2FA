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
- [x] HPA для API (autoscaling по CPU).
- [x] Экспорт и хранение конфигов/манифестов (GitOps-структура).

## P2 (желательно)
- [x] NetworkPolicy для изоляции компонентов.
- [x] RBAC/ServiceAccount с минимальными правами.
- [x] SecurityContext (`runAsNonRoot`, `runAsUser`).
- [x] DR‑план с процедурами восстановления.
- [x] Alertmanager и интеграции.
- [x] SSL для PostgreSQL (`sslmode=disable` заменить).
- [x] Ingress rate‑limit на уровне ingress.
- [x] Прод‑домены WebAuthn в гайдах (без `2fa.local`).
- [x] Экспорт дашбордов Grafana и инструкции по импорту.
- [x] Политика ретенции логов/метрик и её документирование.
- [x] Версионность и архивирование релизной документации.
- [x] Удаление дублей доменных инструкций (RADIUS/доступ).
- [x] Инвентаризация скриптов и утилит.
- [x] FAQ/глоссарий терминов.
- [x] Политика версий API и обратной совместимости.
- [x] Политика управления секретами (ротация/доступы).
- [x] Политика управления доступом к логам и метрикам.
- [x] Политика управления доступом к админке и RADIUS.
