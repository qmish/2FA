# Скрипт для настройки доступа через доменное имя 2fa.local

Write-Host "`n=== НАСТРОЙКА ДОСТУПА ЧЕРЕЗ ДОМЕН 2FA.LOCAL ===" -ForegroundColor Cyan

# Проверка прав администратора
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "`n⚠ Требуются права администратора для изменения hosts файла" -ForegroundColor Yellow
    Write-Host "Запустите скрипт от имени администратора или добавьте запись вручную" -ForegroundColor Yellow
    Write-Host "`nДобавьте в файл $env:SystemRoot\System32\drivers\etc\hosts:" -ForegroundColor White
    Write-Host "127.0.0.1`t2fa.local" -ForegroundColor Cyan
    Write-Host "`nИли запустите PowerShell от имени администратора и выполните:" -ForegroundColor Yellow
    Write-Host "  .\scripts\setup-domain.ps1" -ForegroundColor White
    exit 1
}

# Проверка Ingress
Write-Host "`n[1/3] Проверяю Ingress..." -ForegroundColor Yellow
$ingress = kubectl get ingress api-server -o jsonpath='{.metadata.name}' 2>&1
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($ingress)) {
    Write-Host "Создаю Ingress..." -ForegroundColor Yellow
    kubectl apply -f docs/k8s/api-ingress.yaml 2>&1 | Out-Null
    Start-Sleep -Seconds 3
}

$ingressHost = kubectl get ingress api-server -o jsonpath='{.spec.rules[0].host}' 2>&1
if ($ingressHost -eq "2fa.local") {
    Write-Host "✅ Ingress настроен для домена 2fa.local" -ForegroundColor Green
} else {
    Write-Host "⚠ Ingress настроен для другого домена: $ingressHost" -ForegroundColor Yellow
    Write-Host "Применяю правильную конфигурацию..." -ForegroundColor Yellow
    kubectl apply -f docs/k8s/api-ingress.yaml 2>&1 | Out-Null
}

# Настройка hosts файла
Write-Host "`n[2/3] Настраиваю hosts файл..." -ForegroundColor Yellow
$hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
$hostsContent = Get-Content $hostsPath -ErrorAction SilentlyContinue

if ($hostsContent -match "2fa\.local") {
    Write-Host "⚠ Запись для 2fa.local уже существует" -ForegroundColor Yellow
    $existingLine = $hostsContent | Select-String -Pattern "2fa\.local"
    Write-Host "Текущая запись: $existingLine" -ForegroundColor White
    
    # Проверяем, правильный ли IP
    if ($existingLine -notmatch "127\.0\.0\.1") {
        Write-Host "Обновляю IP на 127.0.0.1..." -ForegroundColor Yellow
        $newContent = $hostsContent | ForEach-Object {
            if ($_ -match "2fa\.local") {
                "127.0.0.1`t2fa.local"
            } else {
                $_
            }
        }
        $newContent | Set-Content $hostsPath -Force
        Write-Host "✅ Запись обновлена" -ForegroundColor Green
    } else {
        Write-Host "✅ Запись корректна" -ForegroundColor Green
    }
} else {
    Write-Host "Добавляю запись в hosts файл..." -ForegroundColor Yellow
    $newEntry = "`n127.0.0.1`t2fa.local"
    try {
        Add-Content -Path $hostsPath -Value $newEntry -ErrorAction Stop
        Write-Host "✅ Запись добавлена в hosts файл" -ForegroundColor Green
    } catch {
        Write-Host "❌ Ошибка добавления в hosts файл: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
}

# Проверка Traefik и порта
Write-Host "`n[3/3] Проверяю Traefik..." -ForegroundColor Yellow
$traefikPort = kubectl get svc traefik -n kube-system -o jsonpath='{.spec.ports[?(@.port==80)].nodePort}' 2>&1
$traefikIP = kubectl get svc traefik -n kube-system -o jsonpath='{.status.loadBalancer.ingress[0].ip}' 2>&1

if ([string]::IsNullOrWhiteSpace($traefikPort) -or $traefikPort -eq "null") {
    Write-Host "⚠ Не удалось определить порт Traefik" -ForegroundColor Yellow
} else {
    Write-Host "Traefik NodePort: $traefikPort" -ForegroundColor White
}

# Проверка доступности
Write-Host "`nПроверяю доступность через домен..." -ForegroundColor Yellow
Start-Sleep -Seconds 2

$testUrls = @(
    "http://2fa.local/healthz",
    "http://2fa.local/ui/"
)

$available = $false
foreach ($url in $testUrls) {
    try {
        $response = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
        Write-Host "✅ Доступен: $url" -ForegroundColor Green
        $available = $true
        break
    } catch {
        Write-Host "⚠ Недоступен: $url" -ForegroundColor Yellow
    }
}

if (-not $available) {
    # Пробуем через порт Traefik
    if (-not [string]::IsNullOrWhiteSpace($traefikPort) -and $traefikPort -ne "null") {
        Write-Host "`nПробую через порт Traefik..." -ForegroundColor Yellow
        try {
            $response = Invoke-WebRequest -Uri "http://localhost:$traefikPort/healthz" -UseBasicParsing -TimeoutSec 5 -Headers @{Host="2fa.local"} -ErrorAction Stop
            Write-Host "✅ Доступен через порт $traefikPort" -ForegroundColor Green
            Write-Host "`nИспользуйте адрес: http://2fa.local:$traefikPort/ui/" -ForegroundColor Cyan
            $available = $true
        } catch {
            Write-Host "⚠ Не удалось подключиться" -ForegroundColor Yellow
        }
    }
    
    if (-not $available) {
        Write-Host "`n⚠ UI может быть недоступен через домен" -ForegroundColor Yellow
        Write-Host "Возможные причины:" -ForegroundColor White
        Write-Host "  1. Traefik не проброшен на порт 80" -ForegroundColor White
        Write-Host "  2. Нужно перезапустить браузер после изменения hosts" -ForegroundColor White
        Write-Host "  3. Используйте port-forward как временное решение" -ForegroundColor White
    }
}

if ($available) {
    Write-Host "`n=== ГОТОВО ===" -ForegroundColor Green
    Write-Host "`n✅ UI доступен через домен:" -ForegroundColor Green
    Write-Host "  http://2fa.local/ui/" -ForegroundColor Cyan
    Write-Host "`nЕсли не работает, попробуйте:" -ForegroundColor Yellow
    Write-Host "  1. Перезапустить браузер" -ForegroundColor White
    Write-Host "  2. Очистить DNS кэш: ipconfig /flushdns" -ForegroundColor White
    Write-Host "  3. Использовать порт Traefik: http://2fa.local:$traefikPort/ui/" -ForegroundColor White
} else {
    Write-Host "`n=== ЧАСТИЧНО ГОТОВО ===" -ForegroundColor Yellow
    Write-Host "Ingress и hosts файл настроены, но доступ может требовать дополнительной настройки" -ForegroundColor Yellow
}
