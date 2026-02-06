# Скрипт для запуска UI и настройки port-forward

$ErrorActionPreference = "Stop"

Write-Host "=== Запуск UI проекта 2FA ===" -ForegroundColor Cyan

# Проверка статуса подов
Write-Host "`nПроверка статуса подов..." -ForegroundColor Yellow
kubectl get pods -l app=api-server

# Получение имени пода API сервера
$apiPod = kubectl get pods -l app=api-server -o jsonpath='{.items[0].metadata.name}'

if (-not $apiPod) {
    Write-Host "`nОшибка: API сервер не запущен!" -ForegroundColor Red
    Write-Host "Запустите развертывание: .\scripts\deploy-k3d.ps1" -ForegroundColor Yellow
    exit 1
}

Write-Host "`nНайден под: $apiPod" -ForegroundColor Green

# Проверка готовности
$ready = kubectl get pod $apiPod -o jsonpath='{.status.containerStatuses[0].ready}'
if ($ready -ne "true") {
    Write-Host "`nПредупреждение: Под еще не готов. Ожидание..." -ForegroundColor Yellow
    kubectl wait --for=condition=ready pod/$apiPod --timeout=60s
}

# Проверка порта
$port = 8083
$check = netstat -ano | Select-String -Pattern ":$port\s"
if ($check) {
    Write-Host "`nПорт $port занят. Попробуйте другой порт:" -ForegroundColor Yellow
    Write-Host "  kubectl port-forward pod/$apiPod 8085:8080" -ForegroundColor White
    $port = 8085
} else {
    Write-Host "`nИспользуется порт: $port" -ForegroundColor Green
}

Write-Host "`n=== Запуск Port-Forward ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "UI будет доступен по адресу:" -ForegroundColor Green
Write-Host "  http://localhost:$port/ui/" -ForegroundColor White -BackgroundColor DarkBlue
Write-Host ""
Write-Host "Другие эндпоинты:" -ForegroundColor Green
Write-Host "  Health check:  http://localhost:$port/healthz" -ForegroundColor White
Write-Host "  Metrics:       http://localhost:$port/metrics" -ForegroundColor White
Write-Host "  API:           http://localhost:$port/api/v1/" -ForegroundColor White
Write-Host ""
Write-Host "Для остановки нажмите Ctrl+C" -ForegroundColor Yellow
Write-Host ""

# Запуск port-forward
kubectl port-forward pod/$apiPod "$port`:8080"
