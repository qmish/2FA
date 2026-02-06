# Статус сервисов в K3D

## ✅ Успешно запущенные сервисы

### Приложение
- **API Server**: ✅ 2/2 подов в статусе Running
- **RADIUS Server**: ✅ 2/2 подов в статусе Running  
- **Migrate Job**: ✅ Завершен успешно (Completed)

### Инфраструктура
- **PostgreSQL**: ✅ 1/1 подов в статусе Running
- **Redis**: ✅ 1/1 подов в статусе Running

## Статус подов

```
NAME                             READY   STATUS      RESTARTS   AGE
api-server-6674f97c9b-w6dlt      1/1     Running     0          110s
api-server-6674f97c9b-wmq8d      1/1     Running     0          105s
migrate-sc4b2                    0/1     Completed   0          73s
postgres-0                       1/1     Running     0          55m
radius-server-85446547d6-2mff6   1/1     Running     0          105s
radius-server-85446547d6-45qnx   1/1     Running     0          110s
redis-6d977785bf-7r6cz           1/1     Running     0          50m
```

## Сервисы

```
NAME            TYPE        CLUSTER-IP      EXTERNAL-IP   PORT(S)    AGE
api-server      ClusterIP   10.43.100.196   <none>        80/TCP     49m
postgres        ClusterIP   None            <none>        5432/TCP   54m
radius-server   ClusterIP   10.43.158.156   <none>        1812/UDP   49m
redis           ClusterIP   10.43.212.207   <none>        6379/TCP   49m
```

## Проверка работоспособности

### Health Check API
API сервер работает и отвечает на `/healthz` с кодом 200:
```bash
kubectl logs api-server-6674f97c9b-w6dlt | grep healthz
```

### Доступ к сервисам

**Через port-forward:**
```bash
# API Server
kubectl port-forward svc/api-server 8080:80

# Или напрямую к поду
kubectl port-forward pod/api-server-6674f97c9b-w6dlt 8080:8080
```

**Проверка health check:**
```bash
curl http://localhost:8080/healthz
```

## Известные проблемы

1. **Service порт**: Service использует порт 80, но приложение слушает на 8080. Это нормально для Kubernetes - Service маппит внешний порт 80 на внутренний порт 8080 контейнера.

2. **Доступ извне**: Для доступа к API извне кластера используйте:
   - `kubectl port-forward` (для тестирования)
   - Настройте Ingress (для production)

## Следующие шаги

1. ✅ Все сервисы запущены и работают
2. ✅ Миграции базы данных выполнены
3. ⏳ Настроить Ingress для внешнего доступа (опционально)
4. ⏳ Настроить мониторинг и логирование (опционально)

## Команды для проверки

```bash
# Статус всех ресурсов
kubectl get pods,services,deployments,statefulsets

# Логи API сервера
kubectl logs -l app=api-server

# Логи RADIUS сервера
kubectl logs -l app=radius-server

# События кластера
kubectl get events --sort-by='.lastTimestamp'

# Описание пода
kubectl describe pod <имя-пода>
```
