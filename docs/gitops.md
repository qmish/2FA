# GitOps структура

## Рекомендуемая структура
```
deploy/
  k8s/
    base/
    overlays/
      dev/
      prod/
  helm/
    values/
      dev.yaml
      prod.yaml
```

## Принципы
- Все манифесты и значения хранятся в Git.
- Изменения проходят через PR/Code Review.
- Деплой выполняется из Git (Argo CD / Flux).

## Что хранить
- K8s манифесты (Ingress, Service, Deployment, HPA, PDB и т.д.).
- Helm values для окружений.
- Документацию по процедурам деплоя.
