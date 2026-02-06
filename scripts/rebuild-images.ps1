# Скрипт пересборки и импорта образов в K3D

$ErrorActionPreference = "Stop"

Write-Host "=== Пересборка и импорт образов ===" -ForegroundColor Cyan

$CLUSTER_NAME = "2fa-cluster"

# Проверка наличия K3D
$k3dCmd = "k3d"
if (-not (Get-Command k3d -ErrorAction SilentlyContinue)) {
    $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
    $localK3d = Join-Path $scriptDir "k3d.exe"
    if (Test-Path $localK3d) {
        $k3dCmd = $localK3d
    } else {
        Write-Host "Ошибка: K3D не найден" -ForegroundColor Red
        exit 1
    }
}

# Сборка образов
Write-Host "Сборка Docker образов..." -ForegroundColor Green

Write-Host "Сборка api-server..." -ForegroundColor Yellow
docker build -f Dockerfile.api-server -t 2fa/api-server:latest .
if ($LASTEXITCODE -ne 0) {
    Write-Host "Ошибка сборки api-server" -ForegroundColor Red
    exit 1
}

Write-Host "Сборка radius-server..." -ForegroundColor Yellow
docker build -f Dockerfile.radius-server -t 2fa/radius-server:latest .
if ($LASTEXITCODE -ne 0) {
    Write-Host "Ошибка сборки radius-server" -ForegroundColor Red
    exit 1
}

Write-Host "Сборка migrate..." -ForegroundColor Yellow
docker build -f Dockerfile.migrate -t 2fa/migrate:latest .
if ($LASTEXITCODE -ne 0) {
    Write-Host "Ошибка сборки migrate" -ForegroundColor Red
    exit 1
}

# Импорт образов в K3D
Write-Host "Импорт образов в K3D..." -ForegroundColor Green

& $k3dCmd image import 2fa/api-server:latest -c $CLUSTER_NAME
& $k3dCmd image import 2fa/radius-server:latest -c $CLUSTER_NAME
& $k3dCmd image import 2fa/migrate:latest -c $CLUSTER_NAME

Write-Host "Образы успешно импортированы!" -ForegroundColor Green

# Перезапуск подов
Write-Host "Перезапуск подов..." -ForegroundColor Yellow
kubectl delete pod -l app=api-server
kubectl delete pod -l app=radius-server
kubectl delete pod -l job-name=migrate

Write-Host "Готово! Проверьте статус: kubectl get pods" -ForegroundColor Green
