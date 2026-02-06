# Настройка домена radius.2fa.local для RADIUS сервера
# Требуются права администратора для изменения hosts файла.

Write-Host "`n=== НАСТРОЙКА RADIUS ДОМЕНА ===" -ForegroundColor Cyan

# Получаем IP k3d-ноды
Write-Host "`nПолучаю IP k3d-ноды..." -ForegroundColor Yellow
$nodeJson = kubectl get nodes -o json 2>$null | ConvertFrom-Json
$nodeIP = $null
if ($nodeJson -and $nodeJson.items -and $nodeJson.items.Count -gt 0) {
    $addresses = $nodeJson.items[0].status.addresses
    $internal = $addresses | Where-Object { $_.type -eq "InternalIP" } | Select-Object -First 1
    if ($internal) { $nodeIP = $internal.address }
}

if ([string]::IsNullOrWhiteSpace($nodeIP)) {
    Write-Host "⚠ Не удалось автоматически получить IP ноды" -ForegroundColor Yellow
    Write-Host "Введите IP вручную (доступный для ASA/FTD):" -ForegroundColor Yellow
    Write-Host "Пример: 172.18.0.3" -ForegroundColor Gray
    $nodeIP = Read-Host "K3D Node IP"
}

if ([string]::IsNullOrWhiteSpace($nodeIP)) {
    Write-Host "❌ IP не задан" -ForegroundColor Red
    exit 1
}

Write-Host "IP ноды: $nodeIP" -ForegroundColor Green

$hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
$entry = "$nodeIP`tradius.2fa.local"

Write-Host "`nПроверяю hosts файл..." -ForegroundColor Yellow
$hostsContent = Get-Content $hostsPath -ErrorAction SilentlyContinue
if ($hostsContent -match "radius\.2fa\.local") {
    Write-Host "⚠ Запись radius.2fa.local уже существует:" -ForegroundColor Yellow
    $hostsContent | Select-String -Pattern "radius\.2fa\.local"
    Write-Host "Если IP отличается, обновите строку вручную." -ForegroundColor Yellow
    exit 0
}

try {
    Add-Content -Path $hostsPath -Value "`n$entry" -ErrorAction Stop
    Write-Host "✅ Запись добавлена в hosts файл:" -ForegroundColor Green
    Write-Host "  $entry" -ForegroundColor White
} catch {
    Write-Host "❌ Не удалось изменить hosts файл (нужны права администратора)" -ForegroundColor Red
    Write-Host "Добавьте вручную:" -ForegroundColor Yellow
    Write-Host "  $entry" -ForegroundColor White
    exit 1
}

Write-Host "`nГотово. Используйте домен в ASA/FTD:" -ForegroundColor Cyan
Write-Host "  radius.2fa.local (порт 31812/UDP)" -ForegroundColor White
