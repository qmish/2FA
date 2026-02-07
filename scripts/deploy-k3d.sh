#!/bin/bash

set -e

echo "=== Развертывание 2FA в K3D ==="

# Проверка наличия K3D
if ! command -v k3d &> /dev/null; then
    echo "Ошибка: K3D не установлен. Установите его с https://k3d.io/"
    exit 1
fi

# Проверка наличия kubectl
if ! command -v kubectl &> /dev/null; then
    echo "Ошибка: kubectl не установлен"
    exit 1
fi

# Проверка наличия docker
if ! command -v docker &> /dev/null; then
    echo "Ошибка: Docker не установлен"
    exit 1
fi

CLUSTER_NAME="2fa-cluster"

# Создание кластера K3D, если не существует
if k3d cluster list | grep -q "$CLUSTER_NAME"; then
    echo "Кластер $CLUSTER_NAME уже существует"
else
    echo "Создание кластера K3D: $CLUSTER_NAME"
    k3d cluster create $CLUSTER_NAME \
        --port "8080:80@loadbalancer" \
        --port "1812:1812@loadbalancer" \
        --wait
fi

# Настройка kubectl для работы с кластером
kubectl config use-context k3d-$CLUSTER_NAME

echo "=== Сборка Docker образов ==="

# Сборка образов
docker build -f Dockerfile.api-server -t 2fa/api-server:latest .
docker build -f Dockerfile.radius-server -t 2fa/radius-server:latest .
docker build -f Dockerfile.migrate -t 2fa/migrate:latest .

# Импорт образов в K3D
echo "Импорт образов в K3D..."
k3d image import 2fa/api-server:latest -c $CLUSTER_NAME
k3d image import 2fa/radius-server:latest -c $CLUSTER_NAME
k3d image import 2fa/migrate:latest -c $CLUSTER_NAME

echo "=== Развертывание инфраструктуры ==="

# Развертывание PostgreSQL
echo "Развертывание PostgreSQL..."
kubectl apply -f docs/k8s/postgres-statefulset.yaml

# Ожидание готовности PostgreSQL
echo "Ожидание готовности PostgreSQL..."
kubectl wait --for=condition=ready pod -l app=postgres --timeout=120s

# Развертывание Redis
echo "Развертывание Redis..."
kubectl apply -f docs/k8s/redis-pvc.yaml
kubectl apply -f docs/k8s/redis-deployment.yaml

# Ожидание готовности Redis
echo "Ожидание готовности Redis..."
kubectl wait --for=condition=ready pod -l app=redis --timeout=60s

echo "=== Развертывание приложения ==="

# Создание ConfigMap и Secrets
echo "Создание ConfigMap и Secrets..."
kubectl apply -f docs/k8s/api-configmap.yaml
kubectl apply -f docs/k8s/api-secrets.yaml
kubectl apply -f docs/k8s/rbac.yaml

# Запуск миграций
echo "Запуск миграций базы данных..."
kubectl apply -f docs/k8s/migrate-job.yaml

# Ожидание завершения миграций
echo "Ожидание завершения миграций..."
kubectl wait --for=condition=complete job/migrate --timeout=120s || true

# Развертывание API сервера
echo "Развертывание API сервера..."
kubectl apply -f docs/k8s/api-deployment.yaml
kubectl apply -f docs/k8s/api-service.yaml
kubectl apply -f docs/k8s/api-ingress.yaml
kubectl apply -f docs/k8s/api-pdb.yaml
kubectl apply -f docs/k8s/api-servicemonitor.yaml

# Развертывание RADIUS сервера
echo "Развертывание RADIUS сервера..."
kubectl apply -f docs/k8s/radius-deployment.yaml
kubectl apply -f docs/k8s/radius-service.yaml
kubectl apply -f docs/k8s/radius-pdb.yaml

# Ожидание готовности подов
echo "Ожидание готовности подов..."
kubectl wait --for=condition=ready pod -l app=api-server --timeout=120s || true
kubectl wait --for=condition=ready pod -l app=radius-server --timeout=120s || true

echo ""
echo "=== Развертывание завершено ==="
echo ""
echo "Проверка статуса:"
kubectl get pods
kubectl get services
echo ""
echo "API доступен по адресу: http://localhost:8080"
echo "API доступен по домену: http://2fa.local (нужно добавить в hosts)"
echo "Linux/macOS hosts: /etc/hosts"
echo "RADIUS доступен по адресу: localhost:1812"
echo ""
echo "Для просмотра логов:"
echo "  kubectl logs -l app=api-server"
echo "  kubectl logs -l app=radius-server"
