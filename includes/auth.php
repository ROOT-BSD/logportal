<?php
/* LogPortal — auth.php */
require_once __DIR__ . '/db.php';

function startSess(): void {
    if (session_status() !== PHP_SESSION_ACTIVE) {
        session_name('LP_SID');
        session_set_cookie_params([
            'lifetime' => 0,
            'path'     => '/',
            'httponly' => true,
            'samesite' => 'Lax',
            'secure'   => isset($_SERVER['HTTPS']),
        ]);
        session_start();
    }
}

function isAuth(): bool {
    startSess();
    if (empty($_SESSION['uid'])) return false;
    if (time() - ($_SESSION['ts'] ?? 0) > SESSION_TTL) {
        session_unset();
        session_destroy();
        return false;
    }
    $_SESSION['ts'] = time();
    return true;
}

function requireAuth(): void {
    if (!isAuth()) {
        header('Location: index.php?expired=1');
        exit;
    }
}

function currentUser(): array {
    return [
        'id'       => (int)($_SESSION['uid']   ?? 0),
        'username' => $_SESSION['uname'] ?? '',
        'role'     => $_SESSION['role']  ?? 'user',
    ];
}

function doLogin(string $u, string $p): string {
    $st = getDB()->prepare("SELECT id,username,password,role FROM users WHERE username=?");
    $st->execute([trim($u)]);
    $row = $st->fetch();
    if (!$row || !password_verify($p, $row['password'])) return 'Невірний логін або пароль';
    startSess();
    session_regenerate_id(true);
    $_SESSION = ['uid' => $row['id'], 'uname' => $row['username'], 'role' => $row['role'], 'ts' => time()];
    getDB()->prepare("UPDATE users SET last_login=CURRENT_TIMESTAMP WHERE id=?")->execute([$row['id']]);
    return '';
}

function doRegister(string $u, string $p, string $p2, string $email): string {
    if (!$u || !$p)                 return "Заповніть всі обов'язкові поля";
    if (strlen($u) < 3)             return 'Логін — мінімум 3 символи';
    if (!preg_match('/^\w+$/', $u)) return 'Логін: лише a-z, 0-9, _';
    if (strlen($p) < 6)             return 'Пароль — мінімум 6 символів';
    if ($p !== $p2)                 return 'Паролі не збігаються';
    $st = getDB()->prepare("SELECT id FROM users WHERE username=?");
    $st->execute([$u]);
    if ($st->fetch())               return 'Такий логін вже зайнятий';
    getDB()->prepare("INSERT INTO users(username,password,email) VALUES(?,?,?)")
           ->execute([$u, password_hash($p, PASSWORD_DEFAULT), $email ?: null]);
    return '';
}
