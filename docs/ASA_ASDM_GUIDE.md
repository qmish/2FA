# Cisco ASA (ASDM) — AnyConnect + RADIUS (шаблон)

> Шаблон для ASDM с плейсхолдерами:  
> `<ASA_PUBLIC_IP>`, `<ASA_INSIDE_IP>`, `<K3D_NODE_IP>`, `<RADIUS_SECRET>`, `<VPN_POOL_START>`, `<VPN_POOL_END>`, `<DNS_SERVER_1>`, `<DOMAIN_NAME>`

## 0) Что должно быть готово

- RADIUS доступен по `radius.2fa.local:31812/UDP`  
  (домен резолвится в `<K3D_NODE_IP>`, см. `docs/RADIUS_DOMAIN_ACCESS.md`)
- Секрет RADIUS: `<RADIUS_SECRET>` (сейчас `cisco123`)

## 1) Добавить RADIUS сервер

**ASDM → Configuration → Device Management → Users/AAA → AAA Server Groups**

1. Нажмите **Add** → **AAA Server Group**
2. Name: `RADIUS-2FA`
3. Protocol: `RADIUS`
4. Нажмите **OK**

**Добавить сервер в группу:**
1. Выберите `RADIUS-2FA` → **Add** (Server)
2. Interface: `inside`
3. Server Address: `radius.2fa.local` (или `<K3D_NODE_IP>`)
4. Authentication Port: `31812`
5. Accounting Port: `31813` (если не используете — оставьте по умолчанию)
6. Shared Secret: `<RADIUS_SECRET>`
7. Timeout: `5`
8. Retries: `3`
9. **OK**

## 2) Пул адресов для VPN

**ASDM → Configuration → Remote Access VPN → Network (Client) Access → Address Assignment → Address Pools**

1. **Add**
2. Name: `VPN_POOL`
3. Range: `<VPN_POOL_START>` – `<VPN_POOL_END>`
4. Mask: `255.255.255.0`
5. **OK**

## 3) Group Policy

**ASDM → Configuration → Remote Access VPN → Network (Client) Access → Group Policies**

1. **Add** → Name: `GP-ANYCONNECT`
2. **General**:
   - **DNS Servers**: `<DNS_SERVER_1>`
   - **Default Domain**: `<DOMAIN_NAME>`
3. **Advanced → AnyConnect Client**:
   - Allow connections: **Yes**
4. **OK**

## 4) AnyConnect (SSL VPN)

**ASDM → Configuration → Remote Access VPN → Network (Client) Access → AnyConnect Connection Profiles**

1. **Add**
2. Connection Profile Name: `ANYCONNECT-TG`
3. Group Alias (User‑visible): `ANYCONNECT`
4. Client Address Pool: `VPN_POOL`
5. Group Policy: `GP-ANYCONNECT`
6. Authentication: `AAA` → `RADIUS-2FA`
7. **OK**

**ASDM → Configuration → Remote Access VPN → Network (Client) Access → AnyConnect Client**

1. Add AnyConnect images (Windows/macOS)
2. Enable on interface `outside`

## 5) IKEv2 (AnyConnect)

**ASDM → Configuration → Remote Access VPN → Network (Client) Access → IKEv2**

1. **Enable IKEv2 on outside**
2. **Authentication**:
   - Method: `RADIUS`
   - Server Group: `RADIUS-2FA`
3. **IKEv2 Policies**:
   - Encryption: AES‑256
   - Integrity: SHA‑256
   - DH Group: 14
   - PRF: SHA‑256
4. **OK**

## 6) NAT (если нужен выход клиентов в интернет)

**ASDM → Configuration → Firewall → NAT Rules**

1. **Add** (After‑Auto)
2. Source Interface: `inside`
3. Destination Interface: `outside`
4. Source Address: `VPN_POOL`
5. Translated Address: `interface`

## 7) Проверка (ASDM)

**ASDM → Tools → AAA Server Test**

1. Server Group: `RADIUS-2FA`
2. Username: `vpnuser`
3. Password: `test123`
4. **Test**

Ожидаемо:
- Первый тест → `otp_required`
- Второй → `test123:<OTP>` → `Access-Accept`

## 8) Подключение AnyConnect

1. Server: `<ASA_PUBLIC_IP>`  
2. Username: `vpnuser`  
3. Password: `test123` (первый запрос)  
4. Второй вход: `test123:<OTP>`

---

Если нужно — сделаю ASDM‑скриншоты по вашей версии ASA/ASDM.
