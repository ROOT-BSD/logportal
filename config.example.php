<?php
# ════════════════════════════════════════════════════════
#  LogPortal — Конфігурація (config.php)
#
#  1. Скопіюйте цей файл: cp config.example.php config.php
#  2. Заповніть значення нижче
#  3. config.php НЕ потрапляє в Git (.gitignore)
# ════════════════════════════════════════════════════════

# ── Ключ шифрування SSH паролів (AES-256-CBC) ──
# Рівно 32 символи. Згенеруйте командою:
#   php -r "echo bin2hex(random_bytes(16));"
# або:
#   openssl rand -hex 16
define('ENCRYPT_KEY', 'ЗАМІНІТЬ_НА_32_СИМВОЛИ_СВОГО_КЛЮЧА');

# ── Часовий пояс ──
define('APP_TIMEZONE', 'Europe/Kyiv');

# ── Шлях до БД (відносно кореню проєкту) ──
# Зазвичай не потрібно змінювати
define('DB_PATH', __DIR__ . '/data/logportal.db');

# ── Директорія SSH ключів ──
define('KEY_UPLOAD_DIR', __DIR__ . '/uploads/keys/');
