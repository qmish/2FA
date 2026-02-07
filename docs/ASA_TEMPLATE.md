# Шаблон конфигурации Cisco ASA для AnyConnect + RADIUS

> Используйте шаблон и замените значения в угловых скобках:
> - `<ASA_PUBLIC_IP>` — публичный IP/FQDN ASA (для AnyConnect)
> - `<ASA_INSIDE_IP>` — inside IP ASA
> - `<K3D_NODE_IP>` — IP k3d‑ноды (доступный для ASA)
> - `<RADIUS_SECRET>` — RADIUS secret (сейчас `cisco123`)
> - `<VPN_POOL_START>`, `<VPN_POOL_END>` — пул IP для клиентов
> - `<DNS_SERVER_1>` — DNS сервер
> - `<DOMAIN_NAME>` — домен для клиентов

## 1) AAA RADIUS сервер

```cisco
aaa-server RADIUS-2FA protocol radius
aaa-server RADIUS-2FA (inside) host <K3D_NODE_IP>
 key <RADIUS_SECRET>
 authentication-port 31812
 accounting-port 31813
 timeout 5
 retransmit 3
```

> Примечание: используется **NodePort 31812/UDP** (см. `docs/k8s/radius-service.yaml`).
> Если пробросите UDP 1812 напрямую, замените порт на 1812.
> Passkeys/WebAuthn через RADIUS/AnyConnect не поддерживаются — используйте OTP/push/call.

## 2) Пул адресов и групповая политика

```cisco
ip local pool VPN_POOL <VPN_POOL_START>-<VPN_POOL_END> mask 255.255.255.0

group-policy GP-ANYCONNECT internal
group-policy GP-ANYCONNECT attributes
 vpn-tunnel-protocol ssl-client ikev2
 split-tunnel-policy tunnelall
 dns-server value <DNS_SERVER_1>
 default-domain value <DOMAIN_NAME>
```

## 3) Tunnel‑group для AnyConnect (SSL)

```cisco
tunnel-group ANYCONNECT-TG type remote-access
tunnel-group ANYCONNECT-TG general-attributes
 address-pool VPN_POOL
 authentication-server-group RADIUS-2FA
 default-group-policy GP-ANYCONNECT

tunnel-group ANYCONNECT-TG webvpn-attributes
 group-alias ANYCONNECT enable
```

## 4) AnyConnect WebVPN

```cisco
webvpn
 enable outside
 anyconnect image disk0:/anyconnect-win.pkg 1
 anyconnect image disk0:/anyconnect-macos.pkg 2
 anyconnect enable
 tunnel-group-list enable
```

## 5) IKEv2 (AnyConnect)

```cisco
crypto ikev2 policy 10
 encryption aes-256
 integrity sha256
 group 14
 prf sha256
 lifetime seconds 86400

crypto ikev2 enable outside

tunnel-group ANYCONNECT-TG ipsec-attributes
 ikev2 remote-authentication radius
 ikev2 local-authentication pre-shared-key <IKEV2_PSK>
```

> PSK используется для IKEv2‑обмена, а пользователь проходит RADIUS аутентификацию.

## 6) NAT (пример, если нужен)

```cisco
object network OBJ_VPN_POOL
 subnet <VPN_POOL_START> 255.255.255.0

nat (inside,outside) after-auto source dynamic OBJ_VPN_POOL interface
```

## 7) Проверка доступности RADIUS

```cisco
test aaa-server authentication RADIUS-2FA host <K3D_NODE_IP> username vpnuser password test123
```

Ожидаемый ответ:
- Первичный запрос: `otp_required`
- Вторичный: `test123:<OTP>` → `Access-Accept`

## 8) Что менять при финальной настройке

- `<K3D_NODE_IP>` → реальный IP k3d‑ноды, доступный ASA
- `<RADIUS_SECRET>` → тот же, что в `radius_clients`
- Пул IP, DNS, домен
- AnyConnect пакеты (`disk0:/anyconnect-*.pkg`)

---

Если нужно — подготовлю **ASDM шаг‑за‑шагом** или конфиг под конкретную версию ASA/FTD.
