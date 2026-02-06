# Доменное имя для RADIUS сервера

Цель: чтобы ASA/FTD обращалась к RADIUS по **доменному имени**, аналогично UI.

## Рекомендуемое имя

```
radius.2fa.local
```

## Как должно резолвиться

`radius.2fa.local` → `<K3D_NODE_IP>`

> Это IP k3d‑ноды, доступный ASA/FTD в вашей сети.

## Windows (hosts файл)

1) Откройте PowerShell **от имени администратора**  
2) Выполните:

```powershell
Add-Content -Path "C:\Windows\System32\drivers\etc\hosts" -Value "`n<K3D_NODE_IP>`tradius.2fa.local"
```

## Linux/macOS

```bash
echo "<K3D_NODE_IP> radius.2fa.local" | sudo tee -a /etc/hosts
```

## Проверка

```bash
nslookup radius.2fa.local
```

## Использование в ASA/FTD

В конфигурации AAA:

```
aaa-server RADIUS-2FA (inside) host radius.2fa.local
 authentication-port 31812
 key <RADIUS_SECRET>
```

> Порт 31812 — это NodePort (см. `docs/k8s/radius-service.yaml`).

## Важно

- Если `radius.2fa.local` не резолвится с ASA/FTD, добавьте запись в **DNS вашей сети**.
- Hosts файл поможет только для локального теста на одной машине.
