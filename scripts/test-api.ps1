# Скрипт для тестирования API

Write-Host "=== Тестирование API 2FA ===" -ForegroundColor Cyan

# Проверка доступности подов
Write-Host "`nПроверка подов..." -ForegroundColor Yellow
kubectl get pods -l app=api-server

# Получение имени пода
$podName = kubectl get pods -l app=api-server -o jsonpath='{.items[0].metadata.name}'
Write-Host "`nИспользуется под: $podName" -ForegroundColor Green

# Тест через exec внутри пода
Write-Host "`nТест health check внутри пода..." -ForegroundColor Yellow
kubectl exec $podName -- wget -qO- http://localhost:8080/healthz

# Port-forward к поду
Write-Host "`nЗапуск port-forward на порт 8083..." -ForegroundColor Yellow
Write-Host "Используйте в другом терминале:" -ForegroundColor Cyan
Write-Host "  kubectl port-forward pod/$podName 8083:8080" -ForegroundColor White
Write-Host "`nЗатем откройте: http://localhost:8083/healthz" -ForegroundColor Green

# Альтернатива: через Service
Write-Host "`nИли используйте port-forward к Service:" -ForegroundColor Cyan
Write-Host "  kubectl port-forward svc/api-server 8084:80" -ForegroundColor White
Write-Host "Затем откройте: http://localhost:8084/healthz" -ForegroundColor Green

Write-Host "`nДоступные эндпоинты:" -ForegroundColor Yellow
Write-Host "  GET  /healthz              - Health check" -ForegroundColor White
Write-Host "  GET  /metrics              - Метрики" -ForegroundColor White
Write-Host "  POST /api/v1/auth/login    - Логин" -ForegroundColor White
Write-Host "  POST /api/v1/auth/verify   - Подтверждение 2FA" -ForegroundColor White
Write-Host "  GET  /ui/                  - Web интерфейс" -ForegroundColor White
