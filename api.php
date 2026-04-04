<?php
/* ─────────────────────────────────────────────────────
   LogPortal — api.php
   AJAX API ендпоінт
   ───────────────────────────────────────────────────── */
require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/ssh.php';

header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');

if (!isAuth()) {
    http_response_code(401);
    echo json_encode(['error' => 'Unauthorized']);
    exit;
}

$user   = currentUser();
$db     = getDB();
$action = $_GET['action'] ?? '';

switch ($action) {

    case 'check_status':
        $sid = (int)($_GET['sid'] ?? 0);
        if (!$sid) { echo json_encode(['error' => 'No sid']); exit; }

        $st = $db->prepare("SELECT * FROM servers WHERE id=? AND user_id=?");
        $st->execute([$sid, $user['id']]);
        $srv = $st->fetch();
        if (!$srv) { echo json_encode(['error' => 'Not found']); exit; }

        $conn   = sshConnect($srv);
        $status = $conn['success'] ? 'online' : 'offline';
        $db->prepare("UPDATE servers SET status=?, last_check=CURRENT_TIMESTAMP WHERE id=?")
           ->execute([$status, $sid]);

        echo json_encode([
            'success' => $conn['success'],
            'status'  => $status,
            'error'   => $conn['error'] ?? null,
        ]);
        break;

    // ── SSE: підключення + список файлів журналів ──────────────────────────
    case 'list_logs':
        $sid = (int)($_GET['sid'] ?? 0);
        if (!$sid) { echo json_encode(['error' => 'No sid']); exit; }

        $st = $db->prepare("SELECT * FROM servers WHERE id=? AND user_id=?");
        $st->execute([$sid, $user['id']]);
        $srv = $st->fetch();
        if (!$srv) { echo json_encode(['error' => 'Not found']); exit; }

        // Перемикаємось на SSE
        header('Content-Type: text/event-stream; charset=utf-8');
        header('Cache-Control: no-cache');
        header('X-Accel-Buffering: no'); // вимикаємо nginx-буферизацію
        ob_implicit_flush(true);
        if (ob_get_level()) ob_end_flush();

        function sse(string $event, array $data): void {
            echo "event: {$event}\n";
            echo "data: " . json_encode($data, JSON_UNESCAPED_UNICODE) . "\n\n";
            if (ob_get_level()) ob_flush();
            flush();
        }

        // Крок 1: SSH підключення
        sse('progress', ['step' => 1, 'pct' => 10, 'msg' => 'Встановлення SSH-з\'єднання…']);
        $conn = sshConnect($srv);

        if (!$conn['success']) {
            $db->prepare("UPDATE servers SET status='offline',last_check=CURRENT_TIMESTAMP WHERE id=?")->execute([$sid]);
            sse('error', ['msg' => $conn['error'] ?? 'Не вдалось підключитись']);
            exit;
        }
        $db->prepare("UPDATE servers SET status='online',last_check=CURRENT_TIMESTAMP WHERE id=?")->execute([$sid]);

        // Крок 2: автентифікація пройшла
        sse('progress', ['step' => 2, 'pct' => 28, 'msg' => 'Автентифікація успішна…']);

        // Крок 3: збираємо файли
        sse('progress', ['step' => 3, 'pct' => 36, 'msg' => 'Сканування директорій…']);

        $files = [];
        if (isMikrotik($srv)) {
            sse('progress', ['step' => 3, 'pct' => 55, 'msg' => 'Читання RouterOS Memory Log…']);
            $info = getMikrotikLogInfo($conn);
            $memRec = $info['total'] > 0 ? $info['total'] . ' записів' : 'RAM буфер';
            $files[] = ['path' => '__mikrotik_memory__', 'name' => 'RouterOS Memory Log (' . $memRec . ')', 'size' => 1, 'mikrotik' => true];

            sse('progress', ['step' => 3, 'pct' => 75, 'msg' => 'Отримання файлів на диску…']);
            foreach (array_values(getMikrotikLogFiles($conn)) as $df) {
                if ($df['size'] > 0) $files[] = $df;
            }
        } else {
            // Linux: проходимо директорії з прогресом
            $standardDirs = [
                '/var/log/nginx'   => 'nginx логи…',
                '/var/log/apache2' => 'apache логи…',
                '/var/log'         => 'системні логи…',
            ];
            $seen = [];
            $pct  = 40;
            $inc  = 50 / (count($standardDirs) + 1);

            foreach ($standardDirs as $dir => $label) {
                sse('progress', ['step' => 3, 'pct' => (int)$pct, 'msg' => 'Сканування ' . $label]);
                $pct += $inc;

                $out = sshExec($conn,
                    "find " . escapeshellarg($dir) . " -maxdepth 2 \\( "
                    . "-name 'mail*'       -o -name 'mail*.gz'      "
                    . "-o -name '*access*' -o -name '*access*.gz'   "
                    . "-o -name 'security*'-o -name 'security*.gz'  "
                    . "-o -name 'syslog*'  -o -name 'syslog*.gz'    "
                    . "-o -name '*error*'  -o -name '*error*.gz'    "
                    . "-o -name 'nginx*'                            "
                    . "\\) -type f 2>/dev/null | sort -V | head -150");

                foreach (array_filter(explode("\n", trim($out))) as $f) {
                    $f = trim($f);
                    if (!$f || isset($seen[$f]) || str_contains($f, 'Permission denied')) continue;
                    $seen[$f] = true;
                    $sz = (int)trim(sshExec($conn, "stat -c '%s' " . escapeshellarg($f) . " 2>/dev/null"));
                    $files[] = ['path' => $f, 'name' => basename($f), 'size' => $sz, 'mikrotik' => false];
                }
            }

            // /opt/log/postfix — без фільтру по імені, maxdepth 5
            // sort -rV — від найновішого (2026) до найстарішого
            sse('progress', ['step' => 3, 'pct' => (int)$pct, 'msg' => 'Сканування postfix логів…']);
            $out = sshExec($conn, "find /opt/log/postfix -maxdepth 5 -type f 2>/dev/null | sort -rV | head -2000");
            foreach (array_filter(explode("\n", trim($out))) as $f) {
                $f = trim($f);
                if (!$f || isset($seen[$f]) || str_contains($f, 'Permission denied')) continue;
                $seen[$f] = true;
                $sz = (int)trim(sshExec($conn, "stat -c '%s' " . escapeshellarg($f) . " 2>/dev/null"));
                $files[] = ['path' => $f, 'name' => basename($f), 'size' => $sz, 'mikrotik' => false];
            }
        }

        // Фінал
        sse('progress', ['step' => 3, 'pct' => 98, 'msg' => 'Формування списку (' . count($files) . ' файлів)…']);
        sse('done', ['files' => $files, 'pct' => 100]);
        exit;

    // ── AJAX: аналіз загроз по вибраних файлах ─────────────────────────────
    case 'analyze_threats':
        $sid = (int)($_POST['sid'] ?? 0);
        if (!$sid) { echo json_encode(['error' => 'No sid']); exit; }
        $st = $db->prepare("SELECT * FROM servers WHERE id=? AND (user_id=? OR ?='admin')");
        $st->execute([$sid, $user['id'], $user['role']]);
        $srv = $st->fetch();
        if (!$srv) { echo json_encode(['error' => 'Not found']); exit; }

        $httpPaths = json_decode($_POST['http_files'] ?? '[]', true) ?: [];
        $mailPaths = json_decode($_POST['mail_files'] ?? '[]', true) ?: [];

        $conn = sshConnect($srv);
        if (!$conn['success']) { echo json_encode(['error' => 'SSH failed']); exit; }

        require_once __DIR__ . '/includes/nginx_parser.php';
        require_once __DIR__ . '/includes/postfix_parser.php';

        // ── HTTP аналіз ──
        $nginxStats = null;
        if (!empty($httpPaths)) {
            $rawHttp = '';
            foreach ($httpPaths as $path) {
                $path = trim($path);
                if (!$path) continue;
                if (str_ends_with($path, '.gz')) {
                    $rawHttp .= sshExec($conn, "zcat ".escapeshellarg($path)." 2>/dev/null");
                } else {
                    $rawHttp .= sshExec($conn, "cat ".escapeshellarg($path)." 2>/dev/null");
                }
            }
            if ($rawHttp) $nginxStats = parseNginxLog($rawHttp);
        }

        // ── Mail аналіз ──
        $smtpStats = ['auth_fail_ips'=>[],'total_auth_fail'=>0,'outbound_spike'=>false,
                      'top_ips'=>[],'traffic_by_ip'=>[]];
        if (!empty($mailPaths)) {
            $rawMail = '';
            foreach ($mailPaths as $path) {
                $path = trim($path);
                if (!$path) continue;
                if (str_ends_with($path, '.gz')) {
                    $rawMail .= sshExec($conn, "zcat ".escapeshellarg($path)." 2>/dev/null");
                } else {
                    $rawMail .= sshExec($conn, "cat ".escapeshellarg($path)." 2>/dev/null");
                }
            }
            if ($rawMail) {
                $authFailIps = []; $hourCounts = []; $msgCount = []; $byteCount = [];
                foreach (explode("\n", $rawMail) as $line) {
                    if (str_contains($line,'authentication failed')||str_contains($line,'SASL LOGIN authentication failed')) {
                        if (preg_match('/\[(\d+\.\d+\.\d+\.\d+)\]/', $line, $m)) {
                            $authFailIps[$m[1]] = ($authFailIps[$m[1]]??0)+1;
                            $smtpStats['total_auth_fail']++;
                        }
                    }
                    // відправники/отримувачі — підрахунок листів по IP
                    if (str_contains($line,'client=')) {
                        if (preg_match('/client=\S+\[(\d+\.\d+\.\d+\.\d+)\]/', $line, $m)) {
                            $msgCount[$m[1]] = ($msgCount[$m[1]]??0)+1;
                        }
                    }
                    // трафік по IP (bytes)
                    if (preg_match('/size=(\d+).*client=\S+\[(\d+\.\d+\.\d+\.\d+)\]/', $line, $m)) {
                        $byteCount[$m[2]] = ($byteCount[$m[2]]??0)+(int)$m[1];
                    }
                    if (str_contains($line,'status=sent')&&preg_match('/^\w+\s+\d+\s+(\d+):/', $line, $m)) {
                        $hourCounts[(int)$m[1]] = ($hourCounts[(int)$m[1]]??0)+1;
                    }
                }
                arsort($authFailIps);
                arsort($msgCount);
                arsort($byteCount);
                $smtpStats['auth_fail_ips'] = array_slice($authFailIps, 0, 15, true);
                $smtpStats['top_ips']       = array_slice($msgCount,    0, 10, true);
                $smtpStats['traffic_by_ip'] = array_slice($byteCount,   0, 10, true);
                if (!empty($hourCounts)) {
                    $avg = array_sum($hourCounts)/count($hourCounts);
                    $max = max($hourCounts);
                    $smtpStats['outbound_spike'] = $max>$avg*5 && $max>100;
                    $smtpStats['hour_max'] = $max;
                    $smtpStats['hour_avg'] = round($avg);
                }
            }
        }

        // ── Топ IP по HTTP + трафік ──
        $httpTopIps = [];
        $httpTrafficByIp = [];
        if ($nginxStats) {
            $httpTopIps      = array_slice($nginxStats['top_ips'] ?? [], 0, 10, true);
            $httpTrafficByIp = array_slice($nginxStats['bytes_by_ip'] ?? [], 0, 10, true);
        }

        echo json_encode([
            'nginxStats'     => $nginxStats,
            'smtpStats'      => $smtpStats,
            'httpTopIps'     => $httpTopIps,
            'httpTrafficByIp'=> $httpTrafficByIp,
        ]);
        exit;

    // ── AJAX: список HTTP і mail файлів для вибору в threats.php ────────────
    case 'list_threat_files':
        $sid = (int)($_GET['sid'] ?? 0);
        if (!$sid) { echo json_encode(['error' => 'No sid']); exit; }
        $st = $db->prepare("SELECT * FROM servers WHERE id=? AND (user_id=? OR ?='admin')");
        $st->execute([$sid, $user['id'], $user['role']]);
        $srv = $st->fetch();
        if (!$srv) { echo json_encode(['error' => 'Not found']); exit; }
        $conn = sshConnect($srv);
        if (!$conn['success']) { echo json_encode(['error' => 'SSH failed: '.($conn['error']??'')]); exit; }

        // HTTP лог файли: nginx/apache
        $httpFiles = [];
        $httpDirs  = ['/var/log/nginx','/var/log/apache2','/var/log/httpd','/usr/local/nginx/logs'];
        $seenH = [];
        foreach ($httpDirs as $dir) {
            $out = sshExec($conn, "find ".escapeshellarg($dir)." -maxdepth 3 \\( -name '*access*' -o -name '*error*' \\) -type f 2>/dev/null | xargs -I{} stat --format='%Y %n' {} 2>/dev/null | sort -rn | awk '{print \$2}'");
            foreach (array_filter(explode("\n", trim($out))) as $f) {
                $f = trim($f);
                if (!$f || isset($seenH[$f])) continue;
                $seenH[$f] = true;
                $sz = (int)trim(sshExec($conn, "stat -c '%s' ".escapeshellarg($f)." 2>/dev/null"));
                $httpFiles[] = ['path'=>$f,'name'=>basename($f),'dir'=>dirname($f),'size'=>$sz];
            }
        }
        // Якщо нічого — пошук по /var/log
        if (empty($httpFiles)) {
            $out = sshExec($conn, "find /var/log -maxdepth 3 -name '*access*' -type f 2>/dev/null | xargs -I{} stat --format='%Y %n' {} 2>/dev/null | sort -rn | awk '{print \$2}' | head -50");
            foreach (array_filter(explode("\n", trim($out))) as $f) {
                $f = trim($f);
                if (!$f || isset($seenH[$f])) continue;
                $seenH[$f] = true;
                $sz = (int)trim(sshExec($conn, "stat -c '%s' ".escapeshellarg($f)." 2>/dev/null"));
                $httpFiles[] = ['path'=>$f,'name'=>basename($f),'dir'=>dirname($f),'size'=>$sz];
            }
        }

        // Mail лог файли: postfix/mail
        $mailFiles = [];
        $seenM = [];
        // /var/log mail* — сортуємо по даті модифікації (найновіші перші)
        $out = sshExec($conn, "find /var/log -maxdepth 2 \\( -name 'mail*' -o -name 'maillog*' \\) -type f 2>/dev/null | xargs -I{} stat --format='%Y %n' {} 2>/dev/null | sort -rn | awk '{print \$2}'");
        foreach (array_filter(explode("\n", trim($out))) as $f) {
            $f = trim($f);
            if (!$f || isset($seenM[$f])) continue;
            $seenM[$f] = true;
            $sz = (int)trim(sshExec($conn, "stat -c '%s' ".escapeshellarg($f)." 2>/dev/null"));
            if ($sz === 0) continue; // пропускаємо порожні файли
            $mailFiles[] = ['path'=>$f,'name'=>basename($f),'dir'=>dirname($f),'size'=>$sz];
        }
        // /opt/log/postfix/ — sort -rV вже дає найновіші перші
        $out = sshExec($conn, "find /opt/log/postfix -maxdepth 5 -type f 2>/dev/null | sort -rV | head -500");
        foreach (array_filter(explode("\n", trim($out))) as $f) {
            $f = trim($f);
            if (!$f || isset($seenM[$f])) continue;
            $seenM[$f] = true;
            $sz = (int)trim(sshExec($conn, "stat -c '%s' ".escapeshellarg($f)." 2>/dev/null"));
            if ($sz === 0) continue; // пропускаємо порожні файли
            $mailFiles[] = ['path'=>$f,'name'=>basename($f),'dir'=>dirname($f),'size'=>$sz];
        }

        echo json_encode(['http'=>$httpFiles,'mail'=>$mailFiles]);
        exit;

    default:
        http_response_code(400);
        echo json_encode(['error' => 'Unknown action']);
}
