# Доступ через доменное имя 2fa.local

## Обзор

Настроен доступ к UI через доменное имя `2fa.local` вместо использования port-forward.

## Что настроено

1. ✅ **Ingress** - создан для домена `2fa.local`
2. ✅ **Traefik** - Ingress Controller работает и готов обрабатывать запросы
3. ⚠️ **Hosts файл** - требует ручной настройки (права администратора)

## Настройка hosts файла

### Windows

1. Откройте PowerShell **от имени администратора**

2. Добавьте запись в hosts файл:
```powershell
Add-Content -Path "C:\Windows\System32\drivers\etc\hosts" -Value "`n127.0.0.1`t2fa.local"
```

3. Или откройте файл вручную:
   - Путь: `C:\Windows\System32\drivers\etc\hosts`
   - Добавьте строку: `127.0.0.1   2fa.local`
   - Сохраните файл

### Linux/macOS

```bash
echo "127.0.0.1    2fa.local" | sudo tee -a /etc/hosts
```

## Доступ к UI

После настройки hosts файла UI будет доступен по адресу:

```
http://2fa.local/ui/
```

## Проверка настройки

### 1. Проверка Ingress

```bash
kubectl get ingress api-server
```

Должно показать:
```
NAME         CLASS     HOSTS       ADDRESS      PORTS   AGE
api-server   traefik   2fa.local   172.18.0.3   80      1m
```

### 2. Проверка hosts файла

**Windows:**
```powershell
Get-Content C:\Windows\System32\drivers\etc\hosts | Select-String "2fa.local"
```

**Linux/macOS:**
```bash
grep "2fa.local" /etc/hosts
```

Должно показать:
```
127.0.0.1    2fa.local
```

### 3. Проверка доступности

```bash
# Проверка healthcheck
curl http://2fa.local/healthz

# Проверка UI
curl http://2fa.local/ui/
```

Или откройте в браузере: http://2fa.local/ui/

## Устранение проблем

### UI недоступен через домен

1. **Проверьте hosts файл:**
   - Убедитесь, что запись `127.0.0.1    2fa.local` существует
   - Проверьте, что нет опечаток

2. **Очистите DNS кэш:**

   **Windows:**
   ```powershell
   ipconfig /flushdns
   ```

   **Linux:**
   ```bash
   sudo systemd-resolve --flush-caches
   # или
   sudo resolvectl flush-caches
   ```

   **macOS:**
   ```bash
   sudo dscacheutil -flushcache
   sudo killall -HUP mDNSResponder
   ```

3. **Перезапустите браузер** после изменения hosts файла

4. **Проверьте Ingress:**
   ```bash
   kubectl describe ingress api-server
   ```

5. **Проверьте Traefik:**
   ```bash
   kubectl get svc traefik -n kube-system
   kubectl get pods -n kube-system | grep traefik
   ```

### Traefik недоступен на порту 80

В K3D Traefik может быть доступен через другой порт. Проверьте:

```bash
kubectl get svc traefik -n kube-system
```

Если NodePort отличается от 80, используйте:
```
http://2fa.local:<NODEPORT>/ui/
```

Или настройте проброс порта в K3D при создании кластера:
```bash
k3d cluster create 2fa-cluster --port '80:80@loadbalancer'
```

### Альтернативный доступ

Если домен не работает, можно использовать:

1. **Через port-forward:**
   ```bash
   kubectl port-forward svc/api-server 8080:80
   ```
   Затем: http://localhost:8080/ui/

2. **Через NodePort:**
   ```bash
   kubectl get svc api-server
   ```
   Используйте NodePort из вывода

## Автоматическая настройка

Используйте скрипт для автоматической настройки:

```powershell
# Запустите от имени администратора
.\scripts\setup-domain.ps1
```

Скрипт:
- Проверяет и создает Ingress
- Добавляет запись в hosts файл
- Проверяет доступность

## Структура Ingress

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: api-server
spec:
  rules:
    - host: 2fa.local
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: api-server
                port:
                  number: 80
```

## Дополнительные домены

Для добавления дополнительных доменов отредактируйте `docs/k8s/api-ingress.yaml`:

```yaml
spec:
  rules:
    - host: 2fa.local
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: api-server
                port:
                  number: 80
    - host: api.2fa.local  # Дополнительный домен
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: api-server
                port:
                  number: 80
```

Затем примените изменения:
```bash
kubectl apply -f docs/k8s/api-ingress.yaml
```

И добавьте домены в hosts файл.
