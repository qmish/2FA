# DNS‑инструкции для production‑доменов VPN/RADIUS

Цель: обеспечить стабильную работу AnyConnect/ASA/FTD с RADIUS
и корректный доступ к UI/API по прод‑доменам.

## Рекомендуемые записи
- `ui.example.com` → внешний адрес API (Ingress/LB)
- `api.example.com` → внешний адрес API (Ingress/LB)
- `radius.example.com` → адрес RADIUS (UDP/1812)

> Для RADIUS предпочтителен L4 Load Balancer или VIP.

## Варианты резолвинга RADIUS

### 1) L4 Load Balancer (рекомендуется)
Создайте A‑запись:
```
radius.example.com -> <L4_LB_PUBLIC_IP>
```

### 2) ASA/FTD и DNS вашей сети
Если ASA/FTD резолвит через корпоративный DNS:
- Добавьте A‑запись в корпоративной зоне.
- Убедитесь, что `radius.example.com` доступен с ASA/FTD по UDP/1812.

### 3) Временный вариант через hosts
Использовать только для локального теста:
```
<RADIUS_IP> radius.example.com
```

## Проверка
На рабочей станции или с ASA/FTD:
```
nslookup radius.example.com
```
Проверьте доступность UDP/1812:
```
nc -vz -u radius.example.com 1812
```

## Использование в ASA/FTD
Пример AAA:
```
aaa-server RADIUS-2FA (inside) host radius.example.com
 authentication-port 1812
 key <RADIUS_SECRET>
```

## Связанные документы
- `docs/RADIUS_UDP_BALANCING.md`
- `docs/VPN_PRODUCTION_DEPLOYMENT.md`
- `docs/RADIUS_STATUS.md`
