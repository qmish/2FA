# Развертывание в K3D

## Предварительные требования

- [K3D](https://k3d.io/) установлен и доступен в PATH
- [kubectl](https://kubernetes.io/docs/tasks/tools/) установлен
- [Docker](https://www.docker.com/) установлен и запущен
- Go 1.22+ (для локальной сборки, опционально)

## Быстрое развертывание

### Linux/macOS

```bash
chmod +x scripts/deploy-k3d.sh
./scripts/deploy-k3d.sh
```

### Windows PowerShell

```powershell
.\scripts\deploy-k3d.ps1
```

## Ручное развертывание

### 1. Создание кластера K3D

```bash
k3d cluster create 2fa-cluster \
    --port "8080:80@loadbalancer" \
    --port "1812:1812@loadbalancer" \
    --wait
```

### 2. Сборка Docker образов

```bash
docker build -f Dockerfile.api-server -t 2fa/api-server:latest .
docker build -f Dockerfile.radius-server -t 2fa/radius-server:latest .
docker build -f Dockerfile.migrate -t 2fa/migrate:latest .
```

### 3. Импорт образов в K3D

```bash
k3d image import 2fa/api-server:latest -c 2fa-cluster
k3d image import 2fa/radius-server:latest -c 2fa-cluster
k3d image import 2fa/migrate:latest -c 2fa-cluster
```

### 4. Развертывание инфраструктуры

```bash
# PostgreSQL
kubectl apply -f docs/k8s/postgres-statefulset.yaml
kubectl wait --for=condition=ready pod -l app=postgres --timeout=120s

# Redis
kubectl apply -f docs/k8s/redis-pvc.yaml
kubectl apply -f docs/k8s/redis-deployment.yaml
kubectl wait --for=condition=ready pod -l app=redis --timeout=60s
```

### 5. Развертывание приложения

```bash
# ConfigMap и Secrets
kubectl apply -f docs/k8s/api-configmap.yaml
kubectl apply -f docs/k8s/api-secrets.yaml
kubectl apply -f docs/k8s/rbac.yaml

# Миграции
kubectl apply -f docs/k8s/migrate-job.yaml
kubectl wait --for=condition=complete job/migrate --timeout=120s

# API сервер
kubectl apply -f docs/k8s/api-deployment.yaml
kubectl apply -f docs/k8s/api-service.yaml
kubectl apply -f docs/k8s/api-ingress.yaml
kubectl apply -f docs/k8s/api-pdb.yaml
kubectl apply -f docs/k8s/api-servicemonitor.yaml

# RADIUS сервер
kubectl apply -f docs/k8s/radius-deployment.yaml
kubectl apply -f docs/k8s/radius-service.yaml
kubectl apply -f docs/k8s/radius-pdb.yaml
```

## Проверка статуса

```bash
# Проверка подов
kubectl get pods

# Проверка сервисов
kubectl get services

# Логи API сервера
kubectl logs -l app=api-server

# Логи RADIUS сервера
kubectl logs -l app=radius-server
```

## Доступ к приложению

- **API**: http://localhost:8080
- **API по домену**: http://2fa.local (добавьте `127.0.0.1 2fa.local` в hosts)
- **Health check**: http://localhost:8080/healthz
- **RADIUS**: localhost:1812 (UDP)

## Использование Helm

Альтернативно можно использовать Helm для развертывания:

```bash
helm install 2fa ./docs/helm
```

## Очистка

```bash
# Удаление кластера
k3d cluster delete 2fa-cluster

# Или удаление ресурсов
kubectl delete -f docs/k8s/
```

## Устранение неполадок

### Проблемы с подключением к базе данных

Проверьте, что PostgreSQL готов:
```bash
kubectl logs -l app=postgres
kubectl exec -it $(kubectl get pod -l app=postgres -o jsonpath='{.items[0].metadata.name}') -- psql -U user -d 2fa
```

### Проблемы с миграциями

Проверьте логи job миграций:
```bash
kubectl logs job/migrate
```

### Проблемы с образами

Убедитесь, что образы импортированы в кластер:
```bash
k3d image list -c 2fa-cluster
```
