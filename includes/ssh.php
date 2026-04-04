<?php
/* LogPortal — ssh.php */
require_once __DIR__ . '/db.php';

function sshConnect(array $srv): array {
    $host    = trim($srv['host']);
    $port    = (int)($srv['port'] ?? 22);
    $user    = trim($srv['ssh_user']);
    $type    = $srv['auth_type'];
    $pass    = $srv['ssh_password']   ? decrypt($srv['ssh_password'])   : '';
    $keyPath = trim($srv['key_path']  ?? '');
    $keyPass = $srv['key_passphrase'] ? decrypt($srv['key_passphrase']) : '';

    return extension_loaded('ssh2')
        ? _native($host, $port, $user, $type, $pass, $keyPath, $keyPass)
        : _shell ($host, $port, $user, $type, $pass, $keyPath, $keyPass);
}

function sshExec(array $c, string $cmd): string {
    if (!empty($c['conn'])) {
        $s = @ssh2_exec($c['conn'], "$cmd 2>&1");
        if (!$s) return '';
        stream_set_blocking($s, true);
        $out = stream_get_contents($s); fclose($s);
        return (string)$out;
    }
    return !empty($c['shell']) ? _shellCmd($c, $cmd) : '';
}

function getLogFiles(array $c): array {
    $dirs  = ['/var/log/nginx','/var/log/apache2','/var/log/httpd','/usr/local/nginx/logs',
              '/var/log/named','/var/log/bind','/var/log',
              '/var/log/mikrotik','/disk1/log','/flash/log'];
    $files = [];
    $seen  = [];

    // Стандартні директорії — maxdepth 2
    foreach ($dirs as $d) {
        $out = sshExec($c, "find " . escapeshellarg($d) . " -maxdepth 2 \\( "
            . "-name 'mail*'       -o -name 'mail*.gz'      "
            . "-o -name '*access*' -o -name '*access*.gz'   "
            . "-o -name 'security*' -o -name 'security*.gz' "
            . "-o -name '*mikrotik*' -o -name 'router*.log' "
            . "-o -name 'syslog*'  -o -name 'syslog*.gz'   "
            . "-o -name 'named*'   -o -name 'named*.gz'     "
            . "-o -name 'query*'   -o -name 'query*.gz'     "
            . "-o -name 'bind*'    -o -name 'bind*.gz'      "
            . "\\) -type f 2>/dev/null | sort -V | head -150");
        foreach (array_filter(explode("\n", trim($out))) as $f) {
            $f = trim($f);
            if (!$f || isset($seen[$f]) || str_contains($f, 'Permission denied')) continue;
            $seen[$f] = true;
            $sz = (int)trim(sshExec($c, "stat -c '%s' " . escapeshellarg($f) . " 2>/dev/null"));
            $files[] = ['path' => $f, 'name' => basename($f), 'size' => $sz];
        }
    }

    // /opt/log/postfix/РРРР/ММ/ДД/файл — структура: рік/місяць/день = 3 рівні + файл = maxdepth 4
    // sort -rV — від найновішого року (2026) до найстарішого, щоб свіжі файли не обрізались лімітом
    $out = sshExec($c, "find /opt/log/postfix -maxdepth 5 -type f 2>/dev/null | sort -rV | head -2000");
    foreach (array_filter(explode("\n", trim($out))) as $f) {
        $f = trim($f);
        if (!$f || isset($seen[$f]) || str_contains($f, 'Permission denied')) continue;
        $seen[$f] = true;
        $sz = (int)trim(sshExec($c, "stat -c '%s' " . escapeshellarg($f) . " 2>/dev/null"));
        $files[] = ['path' => $f, 'name' => basename($f), 'size' => $sz, 'dir' => dirname($f)];
    }

    return $files;
}

function getMailLogFiles(array $c): array {
    $files = [];
    $seen  = [];

    // /var/log — стандартні mail логи
    $out = sshExec($c, "find /var/log -maxdepth 2 \\( "
        . "-name 'mail*' -o -name 'mail*.gz' -o -name 'maillog*' "
        . "\\) -type f 2>/dev/null | sort -V | head -100");
    foreach (array_filter(explode("\n", trim($out))) as $f) {
        $f = trim($f);
        if (!$f || isset($seen[$f])) continue;
        $seen[$f] = true;
        $sz = (int)trim(sshExec($c, "stat -c '%s' " . escapeshellarg($f) . " 2>/dev/null"));
        $files[] = ['path' => $f, 'name' => basename($f), 'size' => $sz, 'dir' => dirname($f)];
    }

    // /opt/log/postfix/РРРР/ММ/ДД/файл — maxdepth 5, від найновішого
    $out = sshExec($c, "find /opt/log/postfix -maxdepth 5 -type f 2>/dev/null | sort -rV | head -2000");
    foreach (array_filter(explode("\n", trim($out))) as $f) {
        $f = trim($f);
        if (!$f || isset($seen[$f]) || str_contains($f, 'Permission denied')) continue;
        $seen[$f] = true;
        $sz = (int)trim(sshExec($c, "stat -c '%s' " . escapeshellarg($f) . " 2>/dev/null"));
        $files[] = ['path' => $f, 'name' => basename($f), 'size' => $sz, 'dir' => dirname($f)];
    }

    return $files;
}


/* ══════════════════════════════════════════════════════════
   Mikrotik RouterOS SSH — окремі функції
   RouterOS не підтримує bash/find/cat/grep — тільки CLI
   ══════════════════════════════════════════════════════════ */

/**
 * Виконати команду в RouterOS CLI і повернути текст відповіді.
 * RouterOS SSH повертає pseudo-terminal output з ANSI-escape — очищаємо.
 */
function sshExecMikrotik(array $c, string $cmd): string {
    // RouterOS не підтримує bash: без 2>&1, без escapeshellarg, без pipe
    if (!empty($c['conn'])) {
        // ext-ssh2: передаємо команду без будь-яких bash-доповнень
        $s = @ssh2_exec($c['conn'], $cmd);
        if (!$s) return '';
        stream_set_blocking($s, true);
        $raw = (string)stream_get_contents($s);
        fclose($s);
    } elseif (!empty($c['shell'])) {
        // shell fallback через sshpass/ssh-keygen — команда як є, без лапок навколо
        $base = "-o StrictHostKeyChecking=no -o ConnectTimeout=15 -o LogLevel=ERROR -p {$c['port']}";
        if ($c['type'] === 'password') {
            $full = "{$c['sshpass']} -p " . escapeshellarg($c['pass'])
                  . " ssh $base " . escapeshellarg("{$c['user']}@{$c['host']}")
                  . " " . escapeshellarg($cmd) . " 2>/dev/null";
        } else {
            $pre = '';
            if (!empty($c['keyPass'])) {
                $apf = _askpass($c['keyPass']);
                if ($apf) $pre = "SSH_ASKPASS_REQUIRE=force SSH_ASKPASS=$apf setsid ";
            } else {
                $base .= " -o PasswordAuthentication=no -o PreferredAuthentications=publickey";
            }
            $full = "{$pre}ssh $base -i " . escapeshellarg($c['key'])
                  . ' ' . escapeshellarg("{$c['user']}@{$c['host']}")
                  . ' ' . escapeshellarg($cmd) . ' 2>/dev/null';
            if (!empty($apf)) @unlink($apf);
        }
        $raw = (string)shell_exec($full);
    } else {
        return '';
    }

    // Очищаємо псевдо-термінал RouterOS:
    // ANSI escape sequences
    $raw = preg_replace('/\x1B\[[0-9;]*[a-zA-Z]/', '', $raw);
    // Carriage returns
    $raw = str_replace("\r", "", $raw);
    return $raw;
}

/**
 * Перевірити чи сервер є Mikrotik
 */
function isMikrotik(array $srv): bool {
    return ($srv['device_type'] ?? 'linux') === 'mikrotik';
}

/**
 * Отримати список "топіків" логів Mikrotik та кількість записів
 * Команда: /log print count-only
 */
function getMikrotikLogInfo(array $conn): array {
    // Спочатку count-only
    $out   = sshExecMikrotik($conn, '/log print count-only');
    $total = (int)trim(preg_replace('/[^0-9]/', '', $out));
    // Якщо 0 — спробуємо просто /log print і рахуємо рядки
    if ($total === 0) {
        $raw   = sshExecMikrotik($conn, '/log print');
        $lines = array_filter(array_map('trim', explode("
", $raw)));
        $total = count($lines);
    }
    return ['total' => $total];
}

/**
 * Читає логи Mikrotik через /log print
 * RouterOS повертає рядки формату:
 *   "mar/09/2026 14:23:01 firewall,info forward: ..."
 *
 * @param array  $conn     SSH connection
 * @param int    $limit    Максимум рядків (RouterOS може мати обмеження ~1000 в пам'яті)
 * @param string $topics   Фільтр по topics: "firewall" | "dhcp" | "" (всі)
 * @param int    $days     Скільки днів брати (0 = все що є в буфері)
 */
function readMikrotikLog(array $conn, int $limit = 2000, string $topics = '', int $days = 0): string {
    $cmd = '/log print';
    if ($topics !== '') {
        $safe = preg_replace('/[^a-zA-Z0-9,_-]/', '', $topics);
        $cmd  = '/log print where topics~"' . $safe . '"';
    }
    $raw = sshExecMikrotik($conn, $cmd);
    return _mtClean($raw);
}

function _mtClean(string $raw): string {
    $out = [];
    foreach (explode("\n", $raw) as $line) {
        $lt = ltrim($line);
        if ($lt === '') continue;
        if (str_starts_with($lt, 'Flags:'))    continue;
        if (str_starts_with($lt, 'Columns:'))  continue;
        if (str_starts_with($lt, '# '))        continue;
        if (preg_match('/^[-=]{3,}/', $lt))    continue;
        if (preg_match('/^[A-Z] - /', $lt))    continue;
        $out[] = $line;
    }
    return implode("\n", $out);
}

/**
 * Отримати список файлів логів на Mikrotik (disk logging)
 * /file print — показує файли на flash/disk
 */
function getMikrotikLogFiles(array $conn): array {
    $out   = sshExecMikrotik($conn, '/file print');
    $files = [];

    // RouterOS /file print: колонка SIZE містить "0", "12345", "81.1KiB" тощо
    // Рядок файлу: " 0   log.0.txt   .txt file   0   2026-03-09 16:48:05"
    foreach (explode("\n", $out) as $line) {
        $line = trim($line);
        // Шукаємо рядки з .txt або .log файлами
        if (!preg_match('/\b(\S+\.(?:txt|log))\b/', $line, $m)) continue;
        $fname = $m[1];

        // Парсимо розмір: число (байти) або "12.5KiB" / "1.2MiB"
        $size = 0;
        if (preg_match('/\b(\d+\.?\d*)\s*(KiB|MiB|GiB|B)\b/i', $line, $sm)) {
            $num = (float)$sm[1];
            $unit = strtoupper($sm[2]);
            $size = (int)match($unit) {
                'KIB' => $num * 1024,
                'MIB' => $num * 1024 * 1024,
                'GIB' => $num * 1024 * 1024 * 1024,
                default => $num,
            };
        } elseif (preg_match('/\s(\d+)\s+\d{4}-/', $line, $sm)) {
            $size = (int)$sm[1];  // байти перед датою
        }

        // Пропускаємо порожні файли (size = 0)
        if ($size === 0) continue;

        $files[] = ['path' => $fname, 'name' => $fname, 'size' => $size, 'mikrotik' => true];
    }
    return $files;
}

/**
 * Читати конкретний файл логу з Mikrotik (/file print file=name.txt)
 */
function readMikrotikFile(array $conn, string $filename): string {
    $safe = preg_replace('/[^a-zA-Z0-9._-]/', '', $filename);
    // В RouterOS 7.x читання файлу: /file print file=name виводить вміст
    // Альтернатива: :put [/file get name contents]
    $raw = sshExecMikrotik($conn, ':put [/file get ' . $safe . ' contents]');
    if (empty(trim($raw))) {
        $raw = sshExecMikrotik($conn, '/file print file=' . $safe);
    }
    return $raw;
}

/* ── private ── */

function _native(string $host, int $port, string $user, string $type,
                 string $pass, string $keyPath, string $keyPass): array {
    $conn = @ssh2_connect($host, $port, ['hostkey'=>'ssh-rsa,ssh-ed25519,ecdsa-sha2-nistp256']);
    if (!$conn) return _fail("Не вдалось підключитись до $host:$port");

    if ($type === 'password') {
        return @ssh2_auth_password($conn, $user, $pass)
            ? ['success'=>true,'conn'=>$conn]
            : _fail("Невірний логін ($user) або пароль");
    }

    if (!is_readable($keyPath)) return _fail("Файл ключа недоступний: $keyPath");
    @chmod($keyPath, 0600);

    $pub = _pubKey($keyPath, $keyPass);
    if ($pub && @ssh2_auth_pubkey_file($conn, $user, $pub, $keyPath, $keyPass ?: null)) {
        if (str_starts_with($pub, sys_get_temp_dir())) @unlink($pub);
        return ['success'=>true,'conn'=>$conn];
    }
    if ($pub && str_starts_with($pub, sys_get_temp_dir())) @unlink($pub);
    // fallback
    return _shell($host, $port, $user, $type, $pass, $keyPath, $keyPass);
}

function _shell(string $host, int $port, string $user, string $type,
                string $pass, string $keyPath, string $keyPass): array {
    $base = "-o StrictHostKeyChecking=no -o ConnectTimeout=10 -o LogLevel=ERROR -p $port";

    if ($type === 'password') {
        $sp = trim((string)shell_exec('which sshpass 2>/dev/null'));
        if (!$sp) return _fail('Потрібен sshpass (apt install sshpass) або PHP ext-ssh2');
        $cmd = "$sp -p " . escapeshellarg($pass) . " ssh $base " . escapeshellarg("$user@$host") . " echo LPOK 2>&1";
        $data = ['type'=>'password','host'=>$host,'port'=>$port,'user'=>$user,'pass'=>$pass,'sshpass'=>$sp];
    } else {
        if (!is_readable($keyPath)) return _fail("Файл ключа не знайдено: $keyPath");
        @chmod($keyPath, 0600);
        $base .= " -o PasswordAuthentication=no -o PreferredAuthentications=publickey";
        $pre  = '';
        $apf  = null;
        if ($keyPass) {
            $apf = _askpass($keyPass);
            if ($apf) $pre = "SSH_ASKPASS_REQUIRE=force SSH_ASKPASS=$apf setsid ";
        }
        $cmd  = "{$pre}ssh $base -i " . escapeshellarg($keyPath) . ' ' . escapeshellarg("$user@$host") . " echo LPOK 2>&1";
        $data = ['type'=>'key','host'=>$host,'port'=>$port,'user'=>$user,'key'=>$keyPath,'keyPass'=>$keyPass];
    }

    $out = (string)shell_exec($cmd);
    if (isset($apf) && $apf) @unlink($apf);

    if (str_contains($out, 'LPOK')) return array_merge(['success'=>true,'shell'=>true], $data);
    return _fail(_sshErr($out));
}

function _shellCmd(array $c, string $cmd): string {
    $base = "-o StrictHostKeyChecking=no -o ConnectTimeout=15 -o LogLevel=ERROR -p {$c['port']}";
    if ($c['type'] === 'password') {
        $full = "{$c['sshpass']} -p " . escapeshellarg($c['pass']) . " ssh $base "
              . escapeshellarg("{$c['user']}@{$c['host']}") . ' ' . escapeshellarg($cmd) . ' 2>&1';
    } else {
        $pre = '';
        if (!empty($c['keyPass'])) {
            $apf = _askpass($c['keyPass']);
            if ($apf) $pre = "SSH_ASKPASS_REQUIRE=force SSH_ASKPASS=$apf setsid ";
        } else {
            $base .= " -o PasswordAuthentication=no -o PreferredAuthentications=publickey";
        }
        $full = "{$pre}ssh $base -i " . escapeshellarg($c['key']) . ' '
              . escapeshellarg("{$c['user']}@{$c['host']}") . ' ' . escapeshellarg($cmd) . ' 2>&1';
        if (!empty($apf)) @unlink($apf);
    }
    return (string)shell_exec($full);
}

function _pubKey(string $priv, string $pass): ?string {
    if (file_exists($pub = $priv . '.pub')) return $pub;
    $tmp = sys_get_temp_dir() . '/lp_pub_' . md5($priv . getmypid()) . '.pub';
    $cmd = $pass
        ? sprintf("ssh-keygen -y -P %s -f %s > %s 2>&1", escapeshellarg($pass), escapeshellarg($priv), escapeshellarg($tmp))
        : sprintf("ssh-keygen -y -P '' -f %s > %s 2>&1", escapeshellarg($priv), escapeshellarg($tmp));
    shell_exec($cmd);
    if (file_exists($tmp) && filesize($tmp) > 20) {
        $c = trim(file_get_contents($tmp));
        if (str_starts_with($c, 'ssh-') || str_starts_with($c, 'ecdsa-')) return $tmp;
    }
    @unlink($tmp);
    return null;
}

function _askpass(string $p): ?string {
    $f = tempnam(sys_get_temp_dir(), 'lp_ap_');
    if (!$f) return null;
    file_put_contents($f, "#!/bin/sh\nprintf '%s' " . escapeshellarg($p) . "\n");
    chmod($f, 0700);
    return $f;
}

function _sshErr(string $r): string {
    $l = strtolower($r);
    if (str_contains($l,'permission denied'))   return 'Відмовлено в доступі — невірний ключ або логін. ' . trim($r);
    if (str_contains($l,'connection refused'))  return "З'єднання відхилено — перевірте порт";
    if (str_contains($l,'timed out'))           return 'Час очікування вичерпано';
    if (str_contains($l,'no route'))            return 'Хост недоступний';
    if (str_contains($l,'invalid format'))      return 'Невірний формат ключа. Конвертуйте: ssh-keygen -p -f key -m PEM -N ""';
    if (str_contains($l,'bad permissions'))     return 'Права на ключ занадто широкі — виконайте chmod 600';
    if (str_contains($l,'could not resolve'))   return 'Не вдалось розпізнати хостнейм';
    return trim($r) ?: 'Невідома помилка SSH';
}

function _fail(string $e): array { return ['success'=>false,'error'=>$e]; }

/**
 * Визначити gateway за замовчуванням на Linux-сервері через SSH
 * Пробує кілька команд по черзі, повертає IP або порожній рядок
 */
function detectGateway(array $conn): string {
    // Спроба 1: ip route show default
    $out = sshExec($conn, "ip route show default 2>/dev/null | awk '/default/ {print $3; exit}'");
    $gw  = trim($out);
    if (preg_match('/^(\d{1,3}\.){3}\d{1,3}$/', $gw)) return $gw;

    // Спроба 2: ip route get 8.8.8.8
    $out = sshExec($conn, "ip route get 8.8.8.8 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i==\"via\") {print $(i+1); exit}}'");
    $gw  = trim($out);
    if (preg_match('/^(\d{1,3}\.){3}\d{1,3}$/', $gw)) return $gw;

    // Спроба 3: route -n (старіші системи)
    $out = sshExec($conn, "route -n 2>/dev/null | awk '/^0\\.0\\.0\\.0/ {print $2; exit}'");
    $gw  = trim($out);
    if (preg_match('/^(\d{1,3}\.){3}\d{1,3}$/', $gw)) return $gw;

    // Спроба 4: netstat -rn
    $out = sshExec($conn, "netstat -rn 2>/dev/null | awk '/^0\\.0\\.0\\.0/ {print $2; exit}'");
    $gw  = trim($out);
    if (preg_match('/^(\d{1,3}\.){3}\d{1,3}$/', $gw)) return $gw;

    return '';
}
