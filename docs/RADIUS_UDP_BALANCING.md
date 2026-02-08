# UDP‑балансировка RADIUS в проде

Цель: обеспечить устойчивую работу RADIUS (UDP/1812) для AnyConnect/ASA/FTD
без потери пакетов и с корректным failover.

## Варианты балансировки

### 1) L4 Load Balancer (рекомендуется)
- Балансировка UDP/1812 на несколько RADIUS‑нод.
- Проверка здоровья через HTTP `/healthz` на порту 8090.
- Сохранение реального IP клиента (если требуется аудит).

Подходит для: облачных L4 LB, аппаратных балансировщиков, MetalLB + внешний LB.

### 2) Группа RADIUS‑серверов на ASA/FTD
- В ASA/FTD можно задать несколько `host` в одном `aaa-server`.
- Балансировка/фейловер выполняется на стороне ASA/FTD.
- Хороший вариант, если нет внешнего LB.

### 3) DNS round‑robin
- Самый простой, но без health‑checks и гарантированного failover.
- Использовать только как временное решение.

## Рекомендованная схема
1) Настроить L4 LB для UDP/1812.
2) В LB включить health‑check на `http://<node>:8090/healthz`.
3) Убедиться, что ASA/FTD может достучаться до LB по UDP/1812.
4) При необходимости сохранить real client IP:
   - использовать L4 LB без SNAT, или
   - включить `externalTrafficPolicy: Local` (Kubernetes).

## Kubernetes (пример)
Если используется NodePort:
- RADIUS UDP: NodePort (например, 31812).
- Healthcheck: HTTP 8090 (из `docs/k8s/radius-deployment.yaml`).

Убедитесь, что:
- `RADIUS_SECRET` одинаковый на всех подах.
- синхронизированы версии образов.
- таймауты и повторы в ASA/FTD соответствуют latency сети.

## Минимальные проверки
- `radius_requests_total` растет на всех нодах.
- `radius_reject_total` не аномально высокий.
- `/healthz` отвечает `200 OK` на 8090.

## Полезные ссылки
- `docs/RADIUS_STATUS.md`
- `docs/VPN_PRODUCTION_DEPLOYMENT.md`
- `docs/k8s/radius-service.yaml`
