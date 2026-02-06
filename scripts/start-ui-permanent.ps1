# Скрипт для постоянного доступа к UI через port-forward в фоне

Write-Host "`n=== ЗАПУСК ПОСТОЯННОГО ДОСТУПА К UI ===" -ForegroundColor Cyan

# Останавливаем старые процессы port-forward
Write-Host "`nОстанавливаю старые процессы port-forward..." -ForegroundColor Yellow
Get-Process | Where-Object { 
    $_.ProcessName -eq "kubectl" -or 
    $_.CommandLine -like "*port-forward*api-server*"
} | ForEach-Object {
    try {
        Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
    } catch {}
}
Start-Sleep -Seconds 2

# Проверяем доступность Service
Write-Host "Проверяю Service..." -ForegroundColor Yellow
$svc = kubectl get svc api-server -o jsonpath='{.metadata.name}' 2>&1
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($svc)) {
    Write-Host "❌ Service api-server не найден" -ForegroundColor Red
    exit 1
}

# Получаем порт из Service
$servicePort = kubectl get svc api-server -o jsonpath='{.spec.ports[0].port}' 2>&1
$nodePort = kubectl get svc api-server -o jsonpath='{.spec.ports[0].nodePort}' 2>&1

Write-Host "✅ Service найден" -ForegroundColor Green
Write-Host "  Service port: $servicePort" -ForegroundColor White
if (-not [string]::IsNullOrWhiteSpace($nodePort)) {
    Write-Host "  NodePort: $nodePort" -ForegroundColor White
}

# Локальный порт для доступа
$localPort = 30080
if ($nodePort -and $nodePort -ne "null") {
    $localPort = $nodePort
}

Write-Host "`nЗапускаю port-forward в фоне на порту $localPort..." -ForegroundColor Yellow
$portForwardScript = "kubectl port-forward svc/api-server ${localPort}:${servicePort}"

# Запускаем port-forward в отдельном окне PowerShell
Start-Process powershell -ArgumentList "-NoExit", "-Command", "Write-Host '=== PORT-FORWARD ДЛЯ UI ===' -ForegroundColor Green; Write-Host 'Порт: $localPort -> $servicePort' -ForegroundColor White; Write-Host 'Service: api-server' -ForegroundColor White; Write-Host ''; Write-Host 'Оставьте это окно открытым для постоянного доступа к UI!' -ForegroundColor Yellow; Write-Host ''; $portForwardScript" -WindowStyle Normal

Write-Host "Ожидаю 5 секунд для установки соединения..." -ForegroundColor Yellow
Start-Sleep -Seconds 5

# Проверяем доступность
Write-Host "`nПроверяю доступность UI..." -ForegroundColor Yellow
try {
    $response = Invoke-WebRequest -Uri "http://localhost:$localPort/healthz" -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
    Write-Host "`n✅✅✅ UI ДОСТУПЕН! ✅✅✅" -ForegroundColor Green
    Write-Host "`nОткройте в браузере:" -ForegroundColor Cyan
    Write-Host "  http://localhost:$localPort/ui/" -ForegroundColor White
    Write-Host "`n⚠ Важно: Оставьте окно с port-forward открытым!" -ForegroundColor Yellow
    Write-Host "Если закроете окно, доступ к UI прекратится." -ForegroundColor Yellow
} catch {
    Write-Host "`n⚠ UI пока недоступен, ожидаю еще 5 секунд..." -ForegroundColor Yellow
    Start-Sleep -Seconds 5
    try {
        $response = Invoke-WebRequest -Uri "http://localhost:$localPort/healthz" -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
        Write-Host "`n✅ UI ДОСТУПЕН!" -ForegroundColor Green
        Write-Host "`nОткройте в браузере:" -ForegroundColor Cyan
        Write-Host "  http://localhost:$localPort/ui/" -ForegroundColor White
    } catch {
        Write-Host "`n❌ Не удалось подключиться к UI" -ForegroundColor Red
        Write-Host "Проверьте:" -ForegroundColor Yellow
        Write-Host "  1. Окно с port-forward открыто" -ForegroundColor White
        Write-Host "  2. Поды API сервера работают: kubectl get pods -l app=api-server" -ForegroundColor White
        Write-Host "  3. Service существует: kubectl get svc api-server" -ForegroundColor White
    }
}

Write-Host "`n=== КОНЕЦ ===" -ForegroundColor Cyan
