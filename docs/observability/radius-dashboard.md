# Дашборд RADIUS (витрина мониторинга)

Цель: быстрый контроль стабильности RADIUS (UDP/1812) и качества ответов.

## Основные панели (PromQL)

### 1) Входящий RADIUS трафик (RPS)
```
sum(rate(radius_requests_total[5m]))
```

### 2) Принятия/отклонения/таймауты
```
sum by (result) (rate(radius_requests_total[5m]))
```

### 3) Доля reject и timeout (%)
```
100 * sum(rate(radius_requests_total{result="reject"}[5m])) /
sum(rate(radius_requests_total[5m]))
```
```
100 * sum(rate(radius_requests_total{result="timeout"}[5m])) /
sum(rate(radius_requests_total[5m]))
```

### 4) Ошибки обработки (%)
```
100 * sum(rate(radius_requests_total{result="error"}[5m])) /
sum(rate(radius_requests_total[5m]))
```

### 5) Динамика успехов (accept)
```
sum(rate(radius_requests_total{result="accept"}[5m]))
```

## Рекомендованные пороги
- Reject > 5% в течение 10–15 минут — проверить конфиг ASA/FTD и RADIUS_SECRET.
- Timeout > 1% — проверить сеть/UDP‑доступ, нагрузку и ретраи.
- Error > 1% — проверить логи API/RADIUS и внешние провайдеры.

## Источники
- Метрики: `GET /metrics`
- Документация метрик: `docs/observability.md`
