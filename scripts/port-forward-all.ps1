# Скрипт для запуска port-forward ко всем сервисам в отдельных окнах

$ErrorActionPreference = "Stop"

Write-Host "=== Запуск Port-Forward ко всем сервисам ===" -ForegroundColor Cyan

# Получение имен подов
$apiPod = kubectl get pods -l app=api-server -o jsonpath='{.items[0].metadata.name}'
$radiusPod = kubectl get pods -l app=radius-server -o jsonpath='{.items[0].metadata.name}'
$postgresPod = kubectl get pods -l app=postgres -o jsonpath='{.items[0].metadata.name}'
$redisPod = kubectl get pods -l app=redis -o jsonpath='{.items[0].metadata.name}'

if (-not $apiPod) {
    Write-Host "Ошибка: API сервер не найден" -ForegroundColor Red
    exit 1
}

Write-Host "`nНайденные поды:" -ForegroundColor Green
Write-Host "  API Server:    $apiPod" -ForegroundColor White
if ($radiusPod) {
    Write-Host "  RADIUS Server: $radiusPod" -ForegroundColor White
}
if ($postgresPod) {
    Write-Host "  PostgreSQL:    $postgresPod" -ForegroundColor White
}
if ($redisPod) {
    Write-Host "  Redis:         $redisPod" -ForegroundColor White
}

Write-Host "`n=== Команды для запуска Port-Forward ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "Скопируйте и выполните в отдельных терминалах:" -ForegroundColor Yellow
Write-Host ""
Write-Host "# API Server (UI и API)" -ForegroundColor Green
Write-Host "kubectl port-forward pod/$apiPod 8083:8080" -ForegroundColor White
Write-Host "# UI: http://localhost:8083/ui/" -ForegroundColor Gray
Write-Host ""
if ($radiusPod) {
    Write-Host "# RADIUS Server" -ForegroundColor Green
    Write-Host "kubectl port-forward pod/$radiusPod 1812:1812" -ForegroundColor White
    Write-Host ""
}
if ($postgresPod) {
    Write-Host "# PostgreSQL (для отладки)" -ForegroundColor Green
    Write-Host "kubectl port-forward pod/$postgresPod 5432:5432" -ForegroundColor White
    Write-Host ""
}
if ($redisPod) {
    Write-Host "# Redis (для отладки)" -ForegroundColor Green
    Write-Host "kubectl port-forward pod/$redisPod 6379:6379" -ForegroundColor White
    Write-Host ""
}

Write-Host "Или используйте скрипт для автоматического запуска:" -ForegroundColor Yellow
Write-Host "  .\scripts\start-ui.ps1" -ForegroundColor White
