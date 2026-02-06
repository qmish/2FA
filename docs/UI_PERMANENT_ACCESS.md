# Постоянный доступ к UI без port-forward

## Обзор

UI теперь доступен постоянно через NodePort Service, без необходимости запускать `kubectl port-forward`.

## Настройка

Service `api-server` настроен как `NodePort` с портом `30080`.

## Доступ к UI

### Вариант 1: Через существующий порт 8080 (K3D loadbalancer)

В K3D кластере loadbalancer уже пробрасывает порт 8080:

```
http://localhost:8080/ui/
```

Это самый простой способ - работает сразу без дополнительных настроек!

### Вариант 2: Через NodePort 30080 (если настроен)

```
http://localhost:30080/ui/
```

### Вариант 2: Через IP узла Kubernetes

1. Получите IP узла:
```bash
kubectl get nodes -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}'
```

2. Откройте в браузере:
```
http://<NODE_IP>:30080/ui/
```

### Вариант 3: Через внешний IP (если настроен)

Если у вас настроен внешний балансировщик или вы используете LoadBalancer:
```
http://<EXTERNAL_IP>:30080/ui/
```

## Проверка доступности

```bash
# Проверка healthcheck
curl http://localhost:30080/healthz

# Проверка UI
curl http://localhost:30080/ui/
```

## Использование скрипта для автоматического запуска

Для удобства создан скрипт, который автоматически запускает port-forward:

```powershell
.\scripts\start-ui-permanent.ps1
```

Скрипт:
- Останавливает старые процессы port-forward
- Запускает новый port-forward в отдельном окне
- Проверяет доступность UI
- Показывает адрес для доступа

## Изменение порта

Если порт `30080` занят или вы хотите использовать другой порт, измените `nodePort` в файле `docs/k8s/api-service.yaml`:

```yaml
spec:
  ports:
    - port: 80
      targetPort: 8080
      nodePort: 30080  # Измените на нужный порт (30000-32767)
```

Затем примените изменения:
```bash
kubectl apply -f docs/k8s/api-service.yaml
```

Для K3D также можно добавить проброс порта при создании кластера:
```bash
k3d cluster create 2fa-cluster --port '30080:30080@loadbalancer'
```

## Ограничения NodePort

- Порт должен быть в диапазоне 30000-32767 (если не указан явно)
- Доступен только внутри кластера или через IP узла
- Для внешнего доступа может потребоваться настройка firewall/security groups

## Альтернативы

### LoadBalancer (для облачных провайдеров)

Если вы используете облачный провайдер (AWS, GCP, Azure), можно использовать LoadBalancer:

```yaml
spec:
  type: LoadBalancer
  ports:
    - port: 80
      targetPort: 8080
```

### Ingress (рекомендуется для production)

Для production окружения рекомендуется использовать Ingress:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: api-server
spec:
  rules:
    - host: api.example.com
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

## Устранение проблем

### UI недоступен

1. Проверьте статус Service:
```bash
kubectl get svc api-server
```

2. Проверьте статус подов:
```bash
kubectl get pods -l app=api-server
```

3. Проверьте логи:
```bash
kubectl logs -l app=api-server --tail=50
```

### Порт занят

Если порт `30080` занят, выберите другой порт в диапазоне 30000-32767 и обновите Service.

### Доступ только внутри кластера

NodePort доступен через IP узла. Если нужен доступ снаружи:
- Настройте firewall для разрешения трафика на порт NodePort
- Используйте LoadBalancer (для облачных провайдеров)
- Используйте Ingress с внешним IP
