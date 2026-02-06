# Скрипт для настройки port-forward к подам

$ErrorActionPreference = "Stop"

Write-Host "=== Настройка Port-Forward к сервисам 2FA ===" -ForegroundColor Cyan

# Получение имен подов
$apiPod = kubectl get pods -l app=api-server -o jsonpath='{.items[0].metadata.name}'
$radiusPod = kubectl get pods -l app=radius-server -o jsonpath='{.items[0].metadata.name}'

if (-not $apiPod) {
    Write-Host "Ошибка: API сервер не найден" -ForegroundColor Red
    exit 1
}

Write-Host "`nНайденные поды:" -ForegroundColor Green
Write-Host "  API Server:    $apiPod" -ForegroundColor White
if ($radiusPod) {
    Write-Host "  RADIUS Server: $radiusPod" -ForegroundColor White
}

Write-Host "`n=== Запуск Port-Forward ===" -ForegroundColor Cyan

# Проверка занятости портов
$ports = @{
    "8083" = "API Server (UI и API)"
    "8084" = "RADIUS Server (если нужен)"
}

foreach ($port in $ports.Keys) {
    $check = netstat -ano | Select-String -Pattern ":$port\s"
    if ($check) {
        Write-Host "Порт $port занят, используйте другой порт" -ForegroundColor Yellow
    }
}

Write-Host "`nЗапуск port-forward для API сервера на порт 8083..." -ForegroundColor Yellow
Write-Host "UI будет доступен по адресу: http://localhost:8083/ui/" -ForegroundColor Green
Write-Host "API будет доступен по адресу: http://localhost:8083/api/v1/" -ForegroundColor Green
Write-Host "Health check: http://localhost:8083/healthz" -ForegroundColor Green

Write-Host "`nДля остановки нажмите Ctrl+C" -ForegroundColor Yellow
Write-Host ""

# Запуск port-forward
kubectl port-forward pod/$apiPod 8083:8080
