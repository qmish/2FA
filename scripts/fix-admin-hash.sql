-- Исправление хеша пароля администратора
-- Пароль: admin123

UPDATE users 
SET password_hash = '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy',
    updated_at = now()
WHERE username = 'admin' AND role = 'admin';

-- Проверка
SELECT username, status, role, LENGTH(password_hash) as hash_length, LEFT(password_hash, 10) as hash_start
FROM users 
WHERE username = 'admin';
