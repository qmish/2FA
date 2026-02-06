-- SQL скрипт для создания первого администратора
-- Использование: подключитесь к базе данных и выполните этот скрипт

-- Пароль будет: admin123
-- Хеш bcrypt для пароля "admin123"
-- Для генерации нового хеша используйте: SELECT crypt('your_password', gen_salt('bf'));

INSERT INTO users (id, username, email, password_hash, status, role, created_at, updated_at)
VALUES (
    uuid_generate_v4(),
    'admin',
    'admin@example.com',
    '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy', -- пароль: admin123
    'active',
    'admin',
    now(),
    now()
)
ON CONFLICT (username) DO NOTHING;

-- Проверка создания
SELECT id, username, email, status, role, created_at 
FROM users 
WHERE role = 'admin';
