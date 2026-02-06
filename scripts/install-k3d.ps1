# Скрипт установки K3D для Windows

$ErrorActionPreference = "Stop"

Write-Host "=== Установка K3D ===" -ForegroundColor Cyan

# Проверка наличия K3D
if (Get-Command k3d -ErrorAction SilentlyContinue) {
    Write-Host "K3D уже установлен" -ForegroundColor Green
    k3d version
    exit 0
}

# Создание директории для бинарников
$binDir = "$env:USERPROFILE\.local\bin"
if (-not (Test-Path $binDir)) {
    New-Item -ItemType Directory -Path $binDir -Force | Out-Null
}

# URL для скачивания K3D
$k3dVersion = "v5.7.0"
$k3dUrl = "https://github.com/k3d-io/k3d/releases/download/$k3dVersion/k3d-windows-amd64.exe"
$k3dPath = "$binDir\k3d.exe"

Write-Host "Скачивание K3D $k3dVersion..." -ForegroundColor Yellow

try {
    # Настройка TLS
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
    
    # Скачивание
    $ProgressPreference = 'SilentlyContinue'
    Invoke-WebRequest -Uri $k3dUrl -OutFile $k3dPath -UseBasicParsing
    
    Write-Host "K3D скачан успешно" -ForegroundColor Green
    
    # Добавление в PATH для текущей сессии
    $env:Path += ";$binDir"
    
    # Проверка установки
    if (Test-Path $k3dPath) {
        Write-Host "K3D установлен в: $k3dPath" -ForegroundColor Green
        
        # Попытка запуска
        & $k3dPath version
        
        Write-Host ""
        Write-Host "Для постоянного использования добавьте в PATH:" -ForegroundColor Yellow
        Write-Host "  $binDir" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "Или выполните:" -ForegroundColor Yellow
        Write-Host "  `$env:Path += `";$binDir`"" -ForegroundColor Cyan
        
    } else {
        Write-Host "Ошибка: файл не найден после скачивания" -ForegroundColor Red
        exit 1
    }
    
} catch {
    Write-Host "Ошибка при установке K3D: $_" -ForegroundColor Red
    Write-Host ""
    Write-Host "Альтернативные способы установки:" -ForegroundColor Yellow
    Write-Host "1. Chocolatey: choco install k3d" -ForegroundColor Cyan
    Write-Host "2. Scoop: scoop install k3d" -ForegroundColor Cyan
    Write-Host "3. Ручная установка: https://github.com/k3d-io/k3d/releases" -ForegroundColor Cyan
    exit 1
}
