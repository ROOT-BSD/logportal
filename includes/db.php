<?php
/* LogPortal — db.php */

// ── Конфігурація ──
// Читаємо з config.php (не в Git). Якщо відсутній — дефолтні значення для першого запуску.
$_cfgFile = __DIR__ . '/../config.php';
if (file_exists($_cfgFile)) {
    require_once $_cfgFile;
} else {
    // Fallback — тільки для першого запуску або розробки.
    // Для production скопіюйте config.example.php → config.php і встановіть свій ключ.
    if (!defined('ENCRYPT_KEY'))   define('ENCRYPT_KEY',   'LogPortal_SecureKey_32ByteXXXXXXXX');
    if (!defined('APP_TIMEZONE'))  define('APP_TIMEZONE',  'Europe/Kyiv');
    if (!defined('DB_PATH'))       define('DB_PATH',       __DIR__ . '/../data/logportal.db');
    if (!defined('KEY_UPLOAD_DIR'))define('KEY_UPLOAD_DIR',__DIR__ . '/../uploads/keys/');
}

date_default_timezone_set(defined('APP_TIMEZONE') ? APP_TIMEZONE : 'Europe/Kyiv');

if (!defined('DB_PATH'))        define('DB_PATH',        __DIR__ . '/../data/logportal.db');
if (!defined('KEY_UPLOAD_DIR')) define('KEY_UPLOAD_DIR', __DIR__ . '/../uploads/keys/');
define('SESSION_TTL', 3600);

function getDB(): PDO {
    static $pdo;
    if ($pdo) return $pdo;

    $dir = dirname(DB_PATH);
    if (!is_dir($dir) && !@mkdir($dir, 0750, true)) {
        throw new RuntimeException("Не вдалось створити директорію БД: $dir\nВиконайте: mkdir -p $dir && chown www-data:www-data $dir && chmod 750 $dir");
    }
    if (!is_writable($dir)) {
        throw new RuntimeException("Директорія БД недоступна для запису: $dir\nВиконайте: chown www-data:www-data $dir && chmod 750 $dir");
    }

    $pdo = new PDO('sqlite:' . DB_PATH, null, null, [
        PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ]);
    $pdo->exec('PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA cache_size=4000;');

    $pdo->exec("
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT,
            role TEXT DEFAULT 'user',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_login DATETIME
        );
        CREATE TABLE IF NOT EXISTS servers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            name TEXT NOT NULL, host TEXT NOT NULL, port INTEGER DEFAULT 22,
            ssh_user TEXT NOT NULL, auth_type TEXT NOT NULL CHECK(auth_type IN ('password','key')),
            ssh_password TEXT, key_path TEXT, key_passphrase TEXT,
            description TEXT, device_type TEXT DEFAULT 'linux',
            status TEXT DEFAULT 'unknown', last_check DATETIME,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
        );
        CREATE TABLE IF NOT EXISTS log_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            server_id INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
            log_file TEXT NOT NULL, total_requests INTEGER DEFAULT 0,
            analyzed_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
    ");

    // Таблиця VPN сесій
    $pdo->exec("
        CREATE TABLE IF NOT EXISTS vpn_sessions (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            server_id   INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
            username    TEXT NOT NULL,
            protocol    TEXT DEFAULT 'unknown',
            ip_address  TEXT DEFAULT '',
            connected_at   INTEGER NOT NULL,
            disconnected_at INTEGER,
            duration_sec    INTEGER,
            interface   TEXT DEFAULT '',
            created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        CREATE INDEX IF NOT EXISTS idx_vpn_server    ON vpn_sessions(server_id);
        CREATE INDEX IF NOT EXISTS idx_vpn_user      ON vpn_sessions(username);
        CREATE INDEX IF NOT EXISTS idx_vpn_connected ON vpn_sessions(connected_at);
    ");

    // Міграція: device_type (може не існувати в старих БД)
    try { $pdo->exec("ALTER TABLE servers ADD COLUMN device_type TEXT DEFAULT 'linux'"); } catch (\Throwable) {}

    // Міграція: gateway (IP шлюзу за замовчуванням)
    try { $pdo->exec("ALTER TABLE servers ADD COLUMN gateway TEXT DEFAULT ''"); } catch (\Throwable) {}

    // Міграція: force_password_change — примусова зміна пароля при першому вході
    try { $pdo->exec("ALTER TABLE users ADD COLUMN force_password_change INTEGER DEFAULT 0"); } catch (\Throwable) {}
    // Для адміна за замовчуванням — якщо пароль ще не змінювався (last_login IS NULL)
    try { $pdo->exec("UPDATE users SET force_password_change=1 WHERE role='admin' AND last_login IS NULL AND force_password_change=0"); } catch (\Throwable) {}

    if ((int)$pdo->query("SELECT COUNT(*) FROM users")->fetchColumn() === 0) {
        $pdo->prepare("INSERT INTO users(username,password,email,role) VALUES('admin',?,'admin@logportal.local','admin')")
            ->execute([password_hash('admin123', PASSWORD_DEFAULT)]);
    }
    return $pdo;
}

function encrypt(string $s): string {
    $iv = random_bytes(16);
    return base64_encode($iv . openssl_encrypt($s, 'AES-256-CBC', ENCRYPT_KEY, OPENSSL_RAW_DATA, $iv));
}

function decrypt(string $s): string {
    $d = base64_decode($s);
    return strlen($d) > 16 ? (string)openssl_decrypt(substr($d,16), 'AES-256-CBC', ENCRYPT_KEY, OPENSSL_RAW_DATA, substr($d,0,16)) : '';
}
