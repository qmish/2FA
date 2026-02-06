# Скрипт для запуска UI с правильным port-forward

$ErrorActionPreference = "Stop"

Write-Host "=== Запуск UI проекта 2FA ===" -ForegroundColor Cyan

# Проверка статуса подов
Write-Host "`nПроверка статуса API сервера..." -ForegroundColor Yellow
$pods = kubectl get pods -l app=api-server -o json | ConvertFrom-Json
if ($pods.items.Count -eq 0) {
    Write-Host "❌ API сервер не запущен!" -ForegroundColor Red
    exit 1
}

$apiPod = $pods.items[0].metadata.name
$ready = $pods.items[0].status.containerStatuses[0].ready

if ($ready -ne "true") {
    Write-Host "⏳ Ожидание готовности пода..." -ForegroundColor Yellow
    kubectl wait --for=condition=ready pod/$apiPod --timeout=60s
}

Write-Host "✅ API сервер готов: $apiPod" -ForegroundColor Green

# Остановка старых port-forward процессов
Write-Host "`nОстановка старых port-forward процессов..." -ForegroundColor Yellow
Get-Process kubectl -ErrorAction SilentlyContinue | Where-Object { $_.CommandLine -like "*port-forward*8083*" } | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2

# Проверка занятости порта
$portCheck = netstat -ano | Select-String -Pattern ":8083\s.*LISTENING"
if ($portCheck) {
    Write-Host "⚠ Порт 8083 занят. Освобождаем..." -ForegroundColor Yellow
    $pid = ($portCheck -split '\s+')[-1]
    Stop-Process -Id $pid -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
}

# Запуск port-forward
Write-Host "`nЗапуск port-forward..." -ForegroundColor Yellow
Write-Host "Используется под: $apiPod" -ForegroundColor White
Write-Host "Порт: 8083 -> 8080" -ForegroundColor White

# Запуск в новом окне PowerShell
$scriptBlock = {
    param($podName)
    kubectl port-forward pod/$podName 8083:8080
}

Start-Process powershell -ArgumentList "-NoExit", "-Command", "kubectl port-forward pod/$apiPod 8083:8080" -WindowStyle Normal

Write-Host "`n⏳ Ожидание запуска port-forward..." -ForegroundColor Yellow
Start-Sleep -Seconds 5

# Проверка доступности
Write-Host "`nПроверка доступности UI..." -ForegroundColor Yellow
try {
    $response = Invoke-WebRequest -Uri "http://localhost:8083/healthz" -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
    Write-Host "✅ UI доступен!" -ForegroundColor Green
} catch {
    Write-Host "⚠ Port-forward еще запускается. Подождите 5-10 секунд и обновите страницу." -ForegroundColor Yellow
}

Write-Host "`n=== Инструкции ===" -ForegroundColor Cyan
Write-Host "1. Откройте в браузере: http://localhost:8083/ui/" -ForegroundColor Green
Write-Host "2. Port-forward запущен в отдельном окне PowerShell" -ForegroundColor White
Write-Host "3. НЕ закрывайте окно с port-forward!" -ForegroundColor Yellow
Write-Host "`nДля остановки закройте окно PowerShell с port-forward" -ForegroundColor Gray
