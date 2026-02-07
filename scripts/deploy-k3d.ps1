# Скрипт развертывания 2FA в K3D для Windows PowerShell

$ErrorActionPreference = "Stop"

Write-Host "=== Развертывание 2FA в K3D ===" -ForegroundColor Cyan

# Проверка наличия K3D
$k3dCmd = "k3d"
if (-not (Get-Command k3d -ErrorAction SilentlyContinue)) {
    # Попытка использовать локальный k3d.exe
    $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
    $localK3d = Join-Path $scriptDir "k3d.exe"
    if (Test-Path $localK3d) {
        $k3dCmd = $localK3d
        Write-Host "Используется локальный K3D: $localK3d" -ForegroundColor Yellow
    } else {
        Write-Host "Ошибка: K3D не установлен. Установите его с https://k3d.io/" -ForegroundColor Red
        exit 1
    }
}

# Проверка наличия kubectl
if (-not (Get-Command kubectl -ErrorAction SilentlyContinue)) {
    Write-Host "Ошибка: kubectl не установлен" -ForegroundColor Red
    exit 1
}

# Проверка наличия docker
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Host "Ошибка: Docker не установлен" -ForegroundColor Red
    exit 1
}

$CLUSTER_NAME = "2fa-cluster"

# Создание кластера K3D, если не существует
$clusterExists = & $k3dCmd cluster list | Select-String -Pattern $CLUSTER_NAME
if ($clusterExists) {
    Write-Host "Кластер $CLUSTER_NAME уже существует" -ForegroundColor Yellow
} else {
    Write-Host "Создание кластера K3D: $CLUSTER_NAME" -ForegroundColor Green
    & $k3dCmd cluster create $CLUSTER_NAME `
        --port "8080:80@loadbalancer" `
        --port "1812:1812@loadbalancer" `
        --wait
}

# Настройка kubectl для работы с кластером
kubectl config use-context k3d-$CLUSTER_NAME

Write-Host "=== Сборка Docker образов ===" -ForegroundColor Cyan

# Сборка образов
docker build -f Dockerfile.api-server -t 2fa/api-server:latest .
docker build -f Dockerfile.radius-server -t 2fa/radius-server:latest .
docker build -f Dockerfile.migrate -t 2fa/migrate:latest .

# Импорт образов в K3D
Write-Host "Импорт образов в K3D..." -ForegroundColor Green
& $k3dCmd image import 2fa/api-server:latest -c $CLUSTER_NAME
& $k3dCmd image import 2fa/radius-server:latest -c $CLUSTER_NAME
& $k3dCmd image import 2fa/migrate:latest -c $CLUSTER_NAME

Write-Host "=== Развертывание инфраструктуры ===" -ForegroundColor Cyan

# Развертывание PostgreSQL
Write-Host "Развертывание PostgreSQL..." -ForegroundColor Green
kubectl apply -f docs/k8s/postgres-statefulset.yaml

# Ожидание готовности PostgreSQL
Write-Host "Ожидание готовности PostgreSQL..." -ForegroundColor Yellow
kubectl wait --for=condition=ready pod -l app=postgres --timeout=120s

# Развертывание Redis
Write-Host "Развертывание Redis..." -ForegroundColor Green
kubectl apply -f docs/k8s/redis-pvc.yaml
kubectl apply -f docs/k8s/redis-deployment.yaml

# Ожидание готовности Redis
Write-Host "Ожидание готовности Redis..." -ForegroundColor Yellow
kubectl wait --for=condition=ready pod -l app=redis --timeout=60s

Write-Host "=== Развертывание приложения ===" -ForegroundColor Cyan

# Создание ConfigMap и Secrets
Write-Host "Создание ConfigMap и Secrets..." -ForegroundColor Green
kubectl apply -f docs/k8s/api-configmap.yaml
kubectl apply -f docs/k8s/api-secrets.yaml
kubectl apply -f docs/k8s/rbac.yaml

# Запуск миграций
Write-Host "Запуск миграций базы данных..." -ForegroundColor Green
kubectl apply -f docs/k8s/migrate-job.yaml

# Ожидание завершения миграций
Write-Host "Ожидание завершения миграций..." -ForegroundColor Yellow
kubectl wait --for=condition=complete job/migrate --timeout=120s -ErrorAction SilentlyContinue

# Развертывание API сервера
Write-Host "Развертывание API сервера..." -ForegroundColor Green
kubectl apply -f docs/k8s/api-deployment.yaml
kubectl apply -f docs/k8s/api-service.yaml
kubectl apply -f docs/k8s/api-ingress.yaml
kubectl apply -f docs/k8s/api-pdb.yaml
kubectl apply -f docs/k8s/api-servicemonitor.yaml

# Развертывание RADIUS сервера
Write-Host "Развертывание RADIUS сервера..." -ForegroundColor Green
kubectl apply -f docs/k8s/radius-deployment.yaml
kubectl apply -f docs/k8s/radius-service.yaml
kubectl apply -f docs/k8s/radius-pdb.yaml

# Ожидание готовности подов
Write-Host "Ожидание готовности подов..." -ForegroundColor Yellow
kubectl wait --for=condition=ready pod -l app=api-server --timeout=120s -ErrorAction SilentlyContinue
kubectl wait --for=condition=ready pod -l app=radius-server --timeout=120s -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "=== Развертывание завершено ===" -ForegroundColor Green
Write-Host ""
Write-Host "Проверка статуса:" -ForegroundColor Cyan
kubectl get pods
kubectl get services
Write-Host ""
Write-Host "API доступен по адресу: http://localhost:8080" -ForegroundColor Green
Write-Host "API доступен по домену: http://2fa.local (нужно добавить в hosts)" -ForegroundColor Green
Write-Host "Windows hosts: C:\\Windows\\System32\\drivers\\etc\\hosts" -ForegroundColor Yellow
Write-Host "RADIUS доступен по адресу: localhost:1812" -ForegroundColor Green
Write-Host ""
Write-Host "Для просмотра логов:" -ForegroundColor Cyan
Write-Host "  kubectl logs -l app=api-server"
Write-Host "  kubectl logs -l app=radius-server"
