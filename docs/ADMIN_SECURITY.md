# Защита админского функционала

## Обзор

Весь функционал администрирования защищен и доступен только после авторизации пользователя с ролью `admin`.

## Защита API эндпоинтов

Все админские API эндпоинты защищены через middleware `AdminAuth`, который:

1. ✅ Проверяет наличие токена в заголовке `Authorization: Bearer <token>`
2. ✅ Валидирует токен через `AdminTokenValidator`
3. ✅ **Проверяет, что роль пользователя = `admin`**
4. ✅ Возвращает `401 Unauthorized` если токен отсутствует или невалиден
5. ✅ Возвращает `403 Forbidden` если роль не `admin`

### Защищенные эндпоинты

Все эндпоинты под `/api/v1/admin/*` защищены, кроме:
- `/api/v1/admin/auth/login` - эндпоинт для входа администратора (должен быть открыт)

#### Полный список защищенных эндпоинтов:

**Управление пользователями:**
- `GET /api/v1/admin/users` - список пользователей
- `POST /api/v1/admin/users/create` - создание пользователя
- `POST /api/v1/admin/users/update` - обновление пользователя
- `POST /api/v1/admin/users/delete` - удаление пользователя

**Управление политиками:**
- `GET /api/v1/admin/policies` - список политик
- `POST /api/v1/admin/policies/create` - создание политики
- `POST /api/v1/admin/policies/update` - обновление политики
- `POST /api/v1/admin/policies/delete` - удаление политики

**Управление RADIUS клиентами:**
- `GET /api/v1/admin/radius/clients` - список RADIUS клиентов
- `POST /api/v1/admin/radius/clients/create` - создание RADIUS клиента
- `POST /api/v1/admin/radius/clients/update` - обновление RADIUS клиента
- `POST /api/v1/admin/radius/clients/delete` - удаление RADIUS клиента

**Управление группами:**
- `GET /api/v1/admin/groups` - список групп
- `POST /api/v1/admin/groups/create` - создание группы
- `POST /api/v1/admin/groups/update` - обновление группы
- `POST /api/v1/admin/groups/delete` - удаление группы
- `GET /api/v1/admin/groups/members` - список членов группы
- `POST /api/v1/admin/groups/members/add` - добавление члена группы
- `POST /api/v1/admin/groups/members/remove` - удаление члена группы
- `POST /api/v1/admin/groups/policy` - установка политики группы
- `POST /api/v1/admin/groups/policy/clear` - очистка политики группы

**Управление правами доступа:**
- `GET /api/v1/admin/role-permissions` - получение прав роли
- `POST /api/v1/admin/role-permissions/update` - обновление прав роли

**Аудит и мониторинг:**
- `GET /api/v1/admin/audit/events` - список событий аудита
- `GET /api/v1/admin/audit/export` - экспорт событий аудита
- `GET /api/v1/admin/logins` - история входов
- `GET /api/v1/admin/radius/requests` - запросы RADIUS
- `GET /api/v1/admin/sessions` - список сессий
- `POST /api/v1/admin/sessions/revoke` - отзыв сессии
- `POST /api/v1/admin/sessions/revoke_user` - отзыв всех сессий пользователя
- `GET /api/v1/admin/lockouts` - список блокировок
- `POST /api/v1/admin/lockouts/clear` - очистка блокировок

## Реализация

### Middleware `AdminAuth`

```go
func AdminAuth(validator AdminTokenValidator) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            // 1. Проверка наличия токена
            header := r.Header.Get("Authorization")
            if !strings.HasPrefix(header, "Bearer ") {
                w.WriteHeader(http.StatusUnauthorized)
                return
            }
            
            // 2. Валидация токена
            token := strings.TrimPrefix(header, "Bearer ")
            claims, err := validator.ParseClaims(token)
            if err != nil {
                w.WriteHeader(http.StatusUnauthorized)
                return
            }
            
            // 3. Проверка роли admin
            if claims.Role != string(models.RoleAdmin) {
                w.WriteHeader(http.StatusForbidden)
                return
            }
            
            // 4. Передача claims в контекст
            ctx := context.WithValue(r.Context(), adminClaimsKey{}, claims)
            next.ServeHTTP(w, r.WithContext(ctx))
        })
    }
}
```

### Использование в router

```go
adminAuth := middlewares.AdminAuth(r.AdminToken)
mux.Handle("/api/v1/admin/users", adminAuth(http.HandlerFunc(r.Admin.ListUsers)))
// ... и т.д. для всех админских эндпоинтов
```

## Использование

### 1. Вход администратора

```bash
POST /api/v1/admin/auth/login
Content-Type: application/json

{
  "username": "admin",
  "password": "admin123"
}

# Ответ:
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expires_in": 900
}
```

### 2. Использование токена для доступа к админским эндпоинтам

```bash
GET /api/v1/admin/users
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

### 3. Ошибки

**401 Unauthorized** - токен отсутствует или невалиден:
```json
{
  "status": 401,
  "payload": {
    "error": "unauthorized"
  }
}
```

**403 Forbidden** - роль не `admin`:
```json
{
  "status": 403,
  "payload": {
    "error": "forbidden"
  }
}
```

## UI

UI является SPA (Single Page Application) и проверка авторизации происходит на клиенте через JavaScript. Все админские секции UI требуют наличия валидного админского токена в localStorage.

Админские секции UI:
- Admin login
- Admin sessions
- Admin lockouts
- Admin audit
- Admin users (если реализовано)
- Admin policies (если реализовано)
- и т.д.

## Безопасность

✅ Все админские API эндпоинты защищены  
✅ Проверка роли `admin` обязательна  
✅ Токен передается через заголовок `Authorization`  
✅ Токен имеет срок действия (TTL)  
✅ Эндпоинт входа не защищен (правильно)  

## Тестирование

Запуск тестов:
```bash
go test ./internal/api/middlewares/...
```

Тесты проверяют:
- ✅ Успешная авторизация с ролью `admin`
- ✅ Отклонение запросов с ролью не `admin` (403)
- ✅ Отклонение запросов без токена (401)
- ✅ Отклонение запросов с невалидным токеном (401)
