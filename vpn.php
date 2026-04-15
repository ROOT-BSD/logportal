<?php
/* LogPortal — vpn.php — VPN Session Statistics */
require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/layout.php';

requireAuth();
sendSecurityHeaders();
$user = currentUser();
$db   = getDB();
$sid  = (int)($_GET['sid'] ?? $_SESSION['last_server'] ?? 0);
$sidQ = $sid ? '?sid=' . $sid : '';

$filterUser  = trim($_GET['user']  ?? '');
$filterProto = trim($_GET['proto'] ?? '');
$filterFrom  = trim($_GET['from']  ?? '');
$filterTo    = trim($_GET['to']    ?? '');
$page    = max(1, (int)($_GET['page'] ?? 1));
$perPage = 50;

$servers = $db->query(
    "SELECT id, name FROM servers WHERE user_id=" . (int)$user['id'] . " AND device_type='mikrotik' ORDER BY name"
)->fetchAll();

$srv = null;
if ($sid) {
    $r = $db->prepare("SELECT * FROM servers WHERE id=? AND user_id=?");
    $r->execute([$sid, $user['id']]);
    $srv = $r->fetch() ?: null;
}

$where  = $sid ? "WHERE server_id = " . (int)$sid : "WHERE 1=1";
$params = [];
if ($filterUser  !== '') { $where .= " AND username LIKE ?";  $params[] = "%" . $filterUser . "%"; }
if ($filterProto !== '' && $filterProto !== 'all') { $where .= " AND protocol = ?"; $params[] = $filterProto; }
if ($filterFrom  !== '') { $where .= " AND connected_at >= ?"; $params[] = strtotime($filterFrom); }
if ($filterTo    !== '') { $where .= " AND connected_at <= ?"; $params[] = strtotime($filterTo) + 86399; }

// Очистити VPN сесії
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'clear_sessions') {
    $clearSid = (int)($_POST['sid'] ?? 0);
    if ($clearSid) {
        $r = $db->prepare("SELECT * FROM servers WHERE id=? AND user_id=?");
        $r->execute([$clearSid, $user['id']]);
        if ($r->fetch()) {
            $db->prepare("DELETE FROM vpn_sessions WHERE server_id=?")->execute([$clearSid]);
        }
    }
    header("Location: vpn.php?sid=$clearSid&cleared=1");
    exit;
}


// ── Відправка VPN-звіту на пошту ─────────────────────────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'send_email') {
    $mailSid   = (int)($_POST['sid']        ?? 0);
    $mailTo    = trim($_POST['mail_to']     ?? '');
    $mailFrom  = trim($_POST['mail_from']   ?? '');
    $mailDateF = trim($_POST['mail_date_from'] ?? '');
    $mailDateT = trim($_POST['mail_date_to']   ?? '');

    // Перевірка прав на сервер
    $srvCheck = $db->prepare("SELECT * FROM servers WHERE id=? AND user_id=?");
    $srvCheck->execute([$mailSid, $user['id']]);
    $mailSrv = $srvCheck->fetch();

    $mailErr = '';
    $mailOk  = '';

    if (!$mailSrv)             $mailErr = 'Сервер не знайдено';
    elseif (!filter_var($mailTo, FILTER_VALIDATE_EMAIL)) $mailErr = 'Невірна email-адреса отримувача';
    elseif (!$mailDateF || !$mailDateT) $mailErr = 'Вкажіть обидві дати';
    else {
        // Отримуємо SMTP налаштування
        $getSetting = function(string $key) use ($db): string {
            $r = $db->query("SELECT value FROM settings WHERE key='" . SQLite3::escapeString($key) . "'");
            return $r ? ($r->fetchColumn() ?: '') : '';
        };
        $smtpHost = $getSetting('smtp_host');
        $smtpPort = (int)($getSetting('smtp_port') ?: 25);
        $smtpUser = $getSetting('smtp_user');
        $smtpPass = decrypt($getSetting('smtp_pass'));
        $smtpFrom = $getSetting('smtp_from') ?: ($mailFrom ?: 'logportal@localhost');

        if (!$smtpHost) $mailErr = 'SMTP не налаштований. Перейдіть в Адмін → Налаштування.';
        else {
            // Вибираємо сесії за датами
            $tsFrom = strtotime($mailDateF . ' 00:00:00');
            $tsTo   = strtotime($mailDateT . ' 23:59:59');
            $rptQ   = $db->prepare(
                "SELECT username, protocol, ip_address, connected_at, disconnected_at, duration_sec, interface
                 FROM vpn_sessions
                 WHERE server_id=? AND connected_at>=? AND connected_at<=?
                 ORDER BY connected_at DESC"
            );
            $rptQ->execute([$mailSid, $tsFrom, $tsTo]);
            $rptRows = $rptQ->fetchAll();

            // Зведена статистика за період
            $statQ2 = $db->prepare(
                "SELECT COUNT(*) as total, COUNT(DISTINCT username) as uniq_u,
                        COUNT(DISTINCT ip_address) as uniq_ip,
                        SUM(duration_sec) as total_sec,
                        AVG(duration_sec) as avg_sec
                 FROM vpn_sessions WHERE server_id=? AND connected_at>=? AND connected_at<=?"
            );
            $statQ2->execute([$mailSid, $tsFrom, $tsTo]);
            $rptStat = $statQ2->fetch();

            $fmtDur = function(int $sec): string {
                if ($sec < 60)   return $sec . ' с';
                if ($sec < 3600) return floor($sec/60) . ' хв ' . ($sec%60) . ' с';
                return floor($sec/3600) . ' год ' . floor(($sec%3600)/60) . ' хв';
            };

            // ── HTML листа ───────────────────────────────────────────
            $srvName = htmlspecialchars($mailSrv['name']);
            $period  = htmlspecialchars($mailDateF) . ' — ' . htmlspecialchars($mailDateT);
            $genTime = date('d.m.Y H:i');
            $totalSec = (int)($rptStat['total_sec'] ?? 0);
            $avgSec   = (int)($rptStat['avg_sec']   ?? 0);

            $html  = '<!DOCTYPE html><html><head><meta charset="utf-8">';
            $html .= '<style>body{font-family:Arial,sans-serif;font-size:13px;color:var(--gray-text);background:var(--gray-bg)}';
            $html .= '.wrap{max-width:900px;margin:0 auto;background:var(--white);border-radius:8px;overflow:hidden;box-shadow:0 2px 12px rgba(0,0,0,.1)}';
            $html .= '.head{background:#1F4E79;color:#fff;padding:24px 32px}';
            $html .= '.head h1{margin:0;font-size:22px}.head p{margin:4px 0 0;opacity:.8;font-size:13px}';
            $html .= '.stats{display:flex;gap:0;border-bottom:1px solid var(--gray-border)}';
            $html .= '.stat{flex:1;padding:18px 24px;text-align:center;border-right:1px solid #e0e0e0}';
            $html .= '.stat:last-child{border-right:none}';
            $html .= '.stat .val{font-size:26px;font-weight:bold;color:var(--blue-dark)}';
            $html .= '.stat .lbl{font-size:11px;color:var(--gray-mid);margin-top:2px}';
            $html .= '.body{padding:24px 32px}';
            $html .= 'table{width:100%;border-collapse:collapse;font-size:12px}';
            $html .= 'th{background:#1F4E79;color:#fff;padding:8px 10px;text-align:left;font-weight:600}';
            $html .= 'tr:nth-child(even){background:#f4f7fb}';
            $html .= 'td{padding:7px 10px;border-bottom:1px solid var(--gray-border);vertical-align:middle}';
            // badge стилі — inline безпосередньо в <span> для сумісності з Gmail/Outlook
            $html .= '.active{color:#16a34a;font-weight:600}.foot{background:var(--gray-bg);padding:12px 32px;text-align:center;font-size:11px;color:var(--gray-light);border-top:1px solid #e0e0e0}';
            $html .= '</style></head><body><div class="wrap">';

            // Шапка
            $html .= '<div class="head">';
            $html .= '<h1>📊 VPN-звіт: ' . $srvName . '</h1>';
            $html .= '<p>Період: ' . $period . ' &nbsp;|&nbsp; Сформовано: ' . $genTime . '</p>';
            $html .= '</div>';

            // Картки статистики
            $html .= '<div class="stats">';
            $html .= '<div class="stat"><div class="val">' . ($rptStat['total']  ?? 0) . '</div><div class="lbl">Всього сесій</div></div>';
            $html .= '<div class="stat"><div class="val">' . ($rptStat['uniq_u'] ?? 0) . '</div><div class="lbl">Унікальних користувачів</div></div>';
            $html .= '<div class="stat"><div class="val">' . ($rptStat['uniq_ip']?? 0) . '</div><div class="lbl">Унікальних IP</div></div>';
            $html .= '<div class="stat"><div class="val">' . ($totalSec ? $fmtDur($totalSec) : '—') . '</div><div class="lbl">Загальний час</div></div>';
            $html .= '<div class="stat"><div class="val">' . ($avgSec   ? $fmtDur($avgSec)   : '—') . '</div><div class="lbl">Середня тривалість</div></div>';
            $html .= '</div>';

            // Таблиця сесій
            $html .= '<div class="body">';
            if (empty($rptRows)) {
                $html .= '<p style="text-align:center;color:var(--gray-mid);padding:32px">За вказаний період сесій не знайдено.</p>';
            } else {
                $html .= '<table><thead><tr>';
                $html .= '<th>#</th><th>Користувач</th><th>Протокол</th><th>IP-адреса</th>';
                $html .= '<th>Підключення</th><th>Відключення</th><th>Тривалість</th><th>Інтерфейс</th>';
                $html .= '</tr></thead><tbody>';
                $n = 0;
                foreach ($rptRows as $row) {
                    $n++;
                    $proto = strtolower($row['protocol'] ?? 'ppp');
                    // badge стиль — inline нижче
                    $connTime = $row['connected_at']    ? date('d.m.Y H:i:s', (int)$row['connected_at'])    : '—';
                    $discTime = $row['disconnected_at'] ? date('d.m.Y H:i:s', (int)$row['disconnected_at']) : '<span style="color:#16a34a;font-weight:600">● активна</span>';
                    $dur      = $row['duration_sec']    ? $fmtDur((int)$row['duration_sec'])                 : '—';
                    $ip       = htmlspecialchars($row['ip_address'] ?: '—');
                    $iface    = htmlspecialchars($row['interface']  ?: '—');
                    $uname    = htmlspecialchars($row['username']);
                    $html .= "<tr><td>$n</td><td><b>$uname</b></td>";
                    $badgeStyle = match($proto) {
                        'l2tp' => 'background:#dbeafe;color:#1e40af',
                        'sstp' => 'background:#dcfce7;color:#166534',
                        'ovpn' => 'background:#fef9c3;color:#854d0e',
                        default => 'background:#f3e8ff;color:#6b21a8',
                    };
                    $html .= "<td><span style=\"display:inline-block;padding:2px 8px;border-radius:10px;font-size:11px;font-weight:600;{$badgeStyle}\">" . strtoupper($proto) . "</span></td>";
                    $html .= "<td>$ip</td><td>$connTime</td><td>$discTime</td><td>$dur</td><td>$iface</td></tr>";
                }
                $html .= '</tbody></table>';
                $html .= '<p style="color:var(--gray-mid);font-size:11px;margin-top:8px">Всього рядків: ' . count($rptRows) . '</p>';
            }
            $html .= '</div>';
            $html .= '<div class="foot">LogPortal v2.1.0 &nbsp;|&nbsp; Автоматично сформований звіт</div>';
            $html .= '</div></body></html>';

            // ── Надсилаємо через SMTP ─────────────────────────────────
            // Кодуємо HTML у base64 щоб уникнути пошкодження тегів SMTP-транспортом
            $htmlB64   = chunk_split(base64_encode($html), 76, "\r\n");
            $subject64 = '=?UTF-8?B?' . base64_encode('VPN звіт ' . $mailSrv['name'] . ' (' . $mailDateF . ' — ' . $mailDateT . ')') . '?=';
            $fromName  = '=?UTF-8?B?' . base64_encode('LogPortal') . '?=';

            // Формуємо повідомлення у форматі RFC 2822
            $msgHeaders  = "MIME-Version: 1.0\r\n";
            $msgHeaders .= "Content-Type: text/html; charset=UTF-8\r\n";
            $msgHeaders .= "Content-Transfer-Encoding: base64\r\n";
            $msgHeaders .= "Subject: {$subject64}\r\n";
            $msgHeaders .= "To: {$mailTo}\r\n";
            $msgHeaders .= "From: {$fromName} <{$smtpFrom}>\r\n";
            $msgHeaders .= "X-Mailer: LogPortal/2.0\r\n";
            $msgHeaders .= "Date: " . date('r') . "\r\n";

            $sock = @fsockopen(($smtpPort === 465 ? 'ssl://' : '') . $smtpHost, $smtpPort, $errno, $errstr, 15);
            if (!$sock) {
                $mailErr = "Не вдалось підключитись до SMTP {$smtpHost}:{$smtpPort} — {$errstr}";
            } else {
                $smtp_read = function() use ($sock) {
                    $r = '';
                    while ($line = fgets($sock, 512)) {
                        $r .= $line;
                        if (strlen($line) >= 4 && $line[3] === ' ') break;
                    }
                    return $r;
                };
                $smtp_send = function(string $cmd) use ($sock) {
                    fputs($sock, $cmd . "\r\n");
                };
                $smtp_read(); // 220 banner
                $smtp_send("EHLO logportal");
                $ehlo = $smtp_read();
                // STARTTLS для порту 587
                if ($smtpPort === 587 && str_contains($ehlo, 'STARTTLS')) {
                    $smtp_send("STARTTLS");
                    $smtp_read();
                    stream_socket_enable_crypto($sock, true, STREAM_CRYPTO_METHOD_TLS_CLIENT);
                    $smtp_send("EHLO logportal");
                    $smtp_read();
                }
                // AUTH LOGIN
                if ($smtpUser && $smtpPass) {
                    $smtp_send("AUTH LOGIN");
                    $smtp_read();
                    $smtp_send(base64_encode($smtpUser));
                    $smtp_read();
                    $smtp_send(base64_encode($smtpPass));
                    $authResp = $smtp_read();
                    if (!str_starts_with(trim($authResp), '235')) {
                        $mailErr = 'Помилка автентифікації SMTP: ' . trim($authResp);
                        fclose($sock);
                        goto mail_done;
                    }
                }
                $smtp_send("MAIL FROM:<{$smtpFrom}>");
                $smtp_read();
                $smtp_send("RCPT TO:<{$mailTo}>");
                $rcptResp = $smtp_read();
                if (!str_starts_with(trim($rcptResp), '250') && !str_starts_with(trim($rcptResp), '251')) {
                    $mailErr = 'Помилка RCPT: ' . trim($rcptResp);
                    $smtp_send("QUIT"); fclose($sock);
                    goto mail_done;
                }
                $smtp_send("DATA");
                $smtp_read();
                // Відправляємо заголовки + base64-закодоване тіло
                fputs($sock, $msgHeaders . "\r\n" . $htmlB64 . "\r\n.\r\n");
                $dataResp = $smtp_read();
                if (str_starts_with(trim($dataResp), '250')) {
                    $mailOk = "Звіт успішно надіслано на {$mailTo}";
                } else {
                    $mailErr = 'Помилка надсилання: ' . trim($dataResp);
                }
                $smtp_send("QUIT");
                fclose($sock);
            }
            mail_done:;
        }
    }
}

// CSV export — до HTML
if (isset($_GET['export']) && $_GET['export'] === 'csv') {
    $expQ = $db->prepare("SELECT * FROM vpn_sessions " . $where . " ORDER BY connected_at DESC");
    $expQ->execute($params);
    $rows = $expQ->fetchAll();
    header('Content-Type: text/csv; charset=utf-8');
    header('Content-Disposition: attachment; filename="vpn_sessions_' . date('Y-m-d') . '.csv"');
    header('Cache-Control: no-cache');
    echo "\xEF\xBB\xBF";
    echo "ID,Server,Username,Protocol,IP,Connected,Disconnected,Duration(sec),Interface\n";
    foreach ($rows as $row) {
        echo implode(',', [
            $row['id'], (int)$sid,
            '"' . str_replace('"', '""', $row['username']) . '"',
            $row['protocol'], $row['ip_address'],
            $row['connected_at']    ? date('Y-m-d H:i:s', (int)$row['connected_at'])    : '',
            $row['disconnected_at'] ? date('Y-m-d H:i:s', (int)$row['disconnected_at']) : '',
            $row['duration_sec'] ?? '',
            '"' . str_replace('"', '""', $row['interface']) . '"',
        ]) . "\n";
    }
    exit;
}

// Зведена статистика
$statQ = $db->prepare("SELECT COUNT(*) as total_sessions, COUNT(DISTINCT username) as unique_users,
    COUNT(DISTINCT ip_address) as unique_ips,
    SUM(CASE WHEN duration_sec IS NOT NULL THEN duration_sec ELSE 0 END) as total_sec,
    AVG(CASE WHEN duration_sec IS NOT NULL THEN duration_sec END) as avg_sec,
    MAX(CASE WHEN duration_sec IS NOT NULL THEN duration_sec END) as max_sec,
    COUNT(CASE WHEN disconnected_at IS NULL AND connected_at IS NOT NULL AND connected_at > strftime('%s','now') - 86400 THEN 1 END) as active_now
    FROM vpn_sessions " . $where);
$statQ->execute($params);
$stat = $statQ->fetch();

$topUsersQ = $db->prepare("SELECT username, COUNT(*) as sessions,
    SUM(CASE WHEN duration_sec IS NOT NULL THEN duration_sec ELSE 0 END) as total_sec,
    AVG(CASE WHEN duration_sec IS NOT NULL THEN duration_sec END) as avg_sec,
    MAX(connected_at) as last_seen, COUNT(DISTINCT ip_address) as unique_ips,
    GROUP_CONCAT(DISTINCT protocol) as protocols
    FROM vpn_sessions " . $where . " GROUP BY username ORDER BY sessions DESC LIMIT 15");
$topUsersQ->execute($params);
$topUsers = $topUsersQ->fetchAll();

$topIpQ = $db->prepare("SELECT ip_address, COUNT(*) as sessions, COUNT(DISTINCT username) as users,
    MAX(connected_at) as last_seen
    FROM vpn_sessions " . $where . " AND ip_address != ''
    GROUP BY ip_address ORDER BY sessions DESC LIMIT 15");
$topIpQ->execute($params);
$topIps = $topIpQ->fetchAll();

$protoQ = $db->prepare("SELECT protocol, COUNT(*) as cnt FROM vpn_sessions " . $where . "
    GROUP BY protocol ORDER BY cnt DESC");
$protoQ->execute($params);
$protos = $protoQ->fetchAll();

$hourQ = $db->prepare("SELECT CAST(strftime('%H', datetime(connected_at,'unixepoch','localtime')) AS INTEGER) as hour,
    COUNT(*) as cnt FROM vpn_sessions " . $where . " AND connected_at IS NOT NULL GROUP BY hour ORDER BY hour");
$hourQ->execute($params);
$hourData = array_fill(0, 24, 0);
foreach ($hourQ->fetchAll() as $hr) { $hourData[(int)$hr['hour']] = (int)$hr['cnt']; }

$dayQ = $db->prepare("SELECT date(datetime(connected_at,'unixepoch','localtime')) as day,
    COUNT(*) as cnt FROM vpn_sessions " . $where . " AND connected_at IS NOT NULL
    GROUP BY day ORDER BY day DESC LIMIT 30");
$dayQ->execute($params);
$dayRows = array_reverse($dayQ->fetchAll());

$allProtos = $db->query("SELECT DISTINCT protocol FROM vpn_sessions ORDER BY protocol")->fetchAll(PDO::FETCH_COLUMN);

$offset = ($page - 1) * $perPage;
$countQ = $db->prepare("SELECT COUNT(*) FROM vpn_sessions " . $where);
$countQ->execute($params);
$total = (int)$countQ->fetchColumn();
$pages = max(1, (int)ceil($total / $perPage));

$sessQ = $db->prepare("SELECT * FROM vpn_sessions " . $where . " ORDER BY connected_at DESC LIMIT " . $perPage . " OFFSET " . $offset);
$sessQ->execute($params);
$sessions = $sessQ->fetchAll();

$protoColors = ['l2tp'=>'#2196F3','sstp'=>'#9C27B0','ovpn'=>'#FF9800','pptp'=>'#F44336','pppoe'=>'#4CAF50','ppp'=>'#607D8B','ipsec'=>'#00BCD4'];

function fmtDur(?int $sec): string {
    if ($sec === null) return '—';
    if ($sec < 60)   return $sec . 'с';
    if ($sec < 3600) return floor($sec/60) . 'хв ' . ($sec%60) . 'с';
    return floor($sec/3600) . 'год ' . floor(($sec%3600)/60) . 'хв';
}
function fmtTs(?int $ts): string { return $ts ? date('d.m.Y H:i', $ts) : '—'; }
?>
<!DOCTYPE html>
<html lang="uk">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>VPN Статистика — LogPortal</title>
<link rel="stylesheet" href="css/style.css">
<script>
(function(){var t=localStorage.getItem('lp_theme');if(t)document.documentElement.setAttribute('data-theme',t);})();
</script>
</head>
<body>
<?php renderGovStrip(); renderHeader($user); renderNav($user, 'vpn', $sid); ?>
<main class="main-content"><div class="container">

<div class="page-header" style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px">
  <div>
    <h1 class="page-title">🔐 VPN Статистика</h1>
    <div class="page-subtitle">Сесії · Користувачі · Активність
      <?php if ($srv): ?>
      &nbsp;·&nbsp;<span style="background:#e3f2fd;color:#1565c0;padding:2px 10px;border-radius:10px;font-size:.78rem;font-weight:600">🖥 <?= htmlspecialchars($srv['name']) ?></span>
      <?php endif; ?>
    </div>
  </div>
  <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
    <?php if ((int)$stat['total_sessions'] > 0): ?>
    <a href="vpn.php<?= $sidQ ?>&export=csv&user=<?= urlencode($filterUser) ?>&proto=<?= urlencode($filterProto) ?>&from=<?= urlencode($filterFrom) ?>&to=<?= urlencode($filterTo) ?>"
       style="background:var(--white);border:1px solid var(--gray-border);padding:7px 16px;border-radius:6px;font-size:.82rem;font-weight:600;color:var(--blue-dark);text-decoration:none">⬇ CSV</a>
    <?php if ($sid): ?>
    <button onclick="document.getElementById('email-modal').style.display='flex'"
      style="background:#e8f0fe;border:1px solid #90b4f8;padding:7px 16px;border-radius:6px;font-size:.82rem;font-weight:600;color:#1a56db;cursor:pointer">📧 Надіслати звіт</button>
    <form method="post" onsubmit="return confirm('Видалити всі VPN сесії для цього сервера?')">
      <input type="hidden" name="action" value="clear_sessions">
      <input type="hidden" name="sid" value="<?= $sid ?>">
      <button type="submit" style="background:#fde8e8;border:1px solid #ef9a9a;padding:7px 16px;border-radius:6px;font-size:.82rem;font-weight:600;color:#c62828;cursor:pointer">🗑 Очистити БД</button>
    </form>
    <?php endif; ?>
    <?php endif; ?>
  </div>
</div>

<!-- Вибір сервера -->
<div class="srv-select">
  <label style="font-weight:600;font-size:.85rem">🔶 Mikrotik:</label>
  <form method="get" style="display:flex;gap:8px;align-items:center">
    <select name="sid" onchange="this.form.submit()">
      <option value="">— всі сервери —</option>
      <?php foreach ($servers as $s): ?>
      <option value="<?= $s['id'] ?>" <?= $s['id']==$sid?'selected':'' ?>><?= htmlspecialchars($s['name']) ?></option>
      <?php endforeach; ?>
    </select>
  </form>
</div>

<?php if (isset($_GET['cleared'])): ?>
<div style="background:#e8f5e9;border:1px solid #a5d6a7;color:#1b5e20;padding:12px 18px;border-radius:8px;margin-bottom:16px;font-size:.85rem">
  ✅ VPN сесії очищено. Тепер <a href="logs.php<?= $sidQ ?>" style="color:#1b5e20;font-weight:600">виконайте повторний аналіз логів</a> — IP адреси запишуться правильно.
</div>
<?php endif; ?>
<?php if ((int)$stat['total_sessions'] === 0): ?>
<div class="no-data">
  <div style="font-size:2rem;margin-bottom:12px">🔐</div>
  VPN сесії ще не записані.<br>
  <a href="logs.php<?= $sidQ ?>" style="color:var(--blue-main)">Відкрийте Файли логів</a> та виконайте аналіз Mikrotik-сервера.
</div>
<?php else: ?>

<!-- ── Зведені картки ── -->
<div class="vpn-grid">
  <div class="vpn-card blue">
    <div class="vpn-title">Всього сесій</div>
    <div class="vpn-val" style="color:#1565c0"><?= number_format((int)$stat['total_sessions']) ?></div>
    <div class="vpn-sub"><?= count($protos) ?> протоколів</div>
  </div>
  <div class="vpn-card green">
    <div class="vpn-title">Користувачів</div>
    <div class="vpn-val" style="color:var(--green-ok)"><?= (int)$stat['unique_users'] ?></div>
    <div class="vpn-sub"><?= (int)$stat['unique_ips'] ?> унікальних IP</div>
  </div>
  <div class="vpn-card orange">
    <div class="vpn-title">Загальний час</div>
    <div class="vpn-val" style="color:var(--orange-warn);font-size:1.5rem"><?= fmtDur((int)$stat['total_sec']) ?></div>
    <div class="vpn-sub">середня: <?= fmtDur($stat['avg_sec'] ? (int)$stat['avg_sec'] : null) ?></div>
  </div>
  <div class="vpn-card teal">
    <div class="vpn-title">Найдовша сесія</div>
    <div class="vpn-val" style="color:#00695c;font-size:1.5rem"><?= fmtDur($stat['max_sec'] ? (int)$stat['max_sec'] : null) ?></div>
    <div class="vpn-sub">максимальна тривалість</div>
  </div>
  <?php if ((int)$stat['active_now'] > 0): ?>
  <div class="vpn-card active">
    <div class="vpn-title">● Активні зараз</div>
    <div class="vpn-val" style="color:var(--green-ok)"><?= (int)$stat['active_now'] ?></div>
    <div class="vpn-sub">підключень онлайн</div>
  </div>
  <?php endif; ?>
</div>

<!-- ── Графіки ── -->
<div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:4px">

  <!-- Активність по годинах -->
  <div class="vpn-card blue" style="padding:14px 16px">
    <div class="vpn-title">📈 Активність по годинах</div>
    <?php $maxH = max(array_merge($hourData, [1])); ?>
    <div class="hour-chart">
      <?php foreach ($hourData as $h => $cnt): ?>
      <div class="hour-bar" style="height:<?= max(1, round($cnt/$maxH*56)) ?>px;opacity:<?= $cnt?1:.15 ?>"
           title="<?= $h ?>:00 — <?= $cnt ?> сесій"></div>
      <?php endforeach; ?>
    </div>
    <div style="display:flex;justify-content:space-between;font-size:.62rem;color:var(--gray-light)">
      <span>00:00</span><span>06:00</span><span>12:00</span><span>18:00</span><span>23:00</span>
    </div>
  </div>

  <!-- Протоколи -->
  <div class="vpn-card purple" style="padding:14px 16px">
    <div class="vpn-title">🔌 Протоколи</div>
    <?php $totalP = max(1, array_sum(array_column($protos,'cnt')));
    foreach ($protos as $pr):
      $pct = round($pr['cnt']/$totalP*100);
      $col = $protoColors[strtolower($pr['protocol'])] ?? '#607D8B';
    ?>
    <div style="margin-bottom:7px">
      <div style="display:flex;justify-content:space-between;font-size:.78rem;margin-bottom:2px">
        <span><span style="display:inline-block;width:9px;height:9px;border-radius:2px;background:<?= $col ?>;margin-right:5px;vertical-align:middle"></span>
        <strong><?= strtoupper(htmlspecialchars($pr['protocol'])) ?></strong></span>
        <span style="color:var(--gray-mid)"><?= number_format($pr['cnt']) ?> <span style="color:#bbb">(<?= $pct ?>%)</span></span>
      </div>
      <div class="mini-bar-wrap"><div class="mini-bar" style="width:<?= $pct ?>%;background:<?= $col ?>"></div></div>
    </div>
    <?php endforeach; ?>
  </div>
</div>

<!-- Активність по днях -->
<?php if (count($dayRows) > 1): ?>
<div class="vpn-card teal" style="padding:14px 16px;margin-bottom:4px">
  <div class="vpn-title">📅 Сесії по днях (останні 30 днів)</div>
  <?php $maxD = max(array_merge(array_column($dayRows,'cnt'), [1])); ?>
  <div class="day-chart">
    <?php foreach ($dayRows as $dr): ?>
    <div class="day-bar" style="height:<?= max(1, round($dr['cnt']/$maxD*46)) ?>px"
         title="<?= $dr['day'] ?>: <?= $dr['cnt'] ?> сесій"></div>
    <?php endforeach; ?>
  </div>
  <div style="display:flex;justify-content:space-between;font-size:.62rem;color:var(--gray-light)">
    <span><?= $dayRows[0]['day'] ?? '' ?></span>
    <span><?= $dayRows[count($dayRows)-1]['day'] ?? '' ?></span>
  </div>
</div>
<?php endif; ?>

<!-- ── Топ користувачів ── -->
<div class="section-title">👤 Топ користувачів</div>
<table class="tbl">
  <thead><tr>
    <th>Користувач</th><th>Сесій</th><th>Загальний час</th>
    <th>Середня сесія</th><th>Унікальних IP</th><th>Протоколи</th><th>Остання активність</th>
  </tr></thead>
  <tbody>
  <?php foreach ($topUsers as $u):
    $level = $u['sessions'] > 200 ? 'blue' : ($u['sessions'] > 50 ? 'teal' : 'gray');
  ?>
  <tr>
    <td>
      <a href="vpn.php<?= $sidQ ?>&user=<?= urlencode($u['username']) ?>" style="color:var(--blue-main);font-weight:600">
        <?= htmlspecialchars($u['username']) ?>
      </a>
    </td>
    <td><span class="badge badge-<?= $level ?>"><?= number_format((int)$u['sessions']) ?></span></td>
    <td style="font-weight:600"><?= fmtDur($u['total_sec'] ? (int)$u['total_sec'] : null) ?></td>
    <td style="color:var(--gray-mid)"><?= fmtDur($u['avg_sec'] ? (int)$u['avg_sec'] : null) ?></td>
    <td><?= (int)$u['unique_ips'] ?></td>
    <td>
      <?php foreach (explode(',', $u['protocols'] ?? '') as $p):
        $p = trim($p); if (!$p) continue;
        $col = $protoColors[strtolower($p)] ?? '#607D8B'; ?>
      <span style="background:<?= $col ?>22;color:<?= $col ?>;padding:1px 6px;border-radius:8px;font-size:.68rem;font-weight:700;margin-right:2px"><?= strtoupper(htmlspecialchars($p)) ?></span>
      <?php endforeach; ?>
    </td>
    <td style="font-size:.75rem;color:var(--gray-mid)"><?= fmtTs((int)$u['last_seen']) ?></td>
  </tr>
  <?php endforeach; ?>
  </tbody>
</table>

<!-- ── Топ IP ── -->
<div class="section-title">🌐 Топ IP-адрес</div>
<table class="tbl">
  <thead><tr>
    <th>IP-адреса</th><th>Тип</th><th>Сесій</th><th>Користувачів</th><th>Остання активність</th>
  </tr></thead>
  <tbody>
  <?php foreach ($topIps as $ip):
    $isLocal = str_starts_with($ip['ip_address'],'192.168.') || str_starts_with($ip['ip_address'],'10.') || str_starts_with($ip['ip_address'],'172.');
  ?>
  <tr>
    <td style="font-family:monospace;font-weight:600">
      <a href="vpn.php<?= $sidQ ?>&user=<?= urlencode($ip['ip_address']) ?>" style="color:var(--blue-main)"><?= htmlspecialchars($ip['ip_address']) ?></a>
    </td>
    <td>
      <?php if ($isLocal): ?>
      <span class="badge badge-green">local</span>
      <?php else: ?>
      <span class="badge badge-orange">external</span>
      <?php endif; ?>
    </td>
    <td><span class="badge badge-blue"><?= number_format((int)$ip['sessions']) ?></span></td>
    <td><?= (int)$ip['users'] ?></td>
    <td style="font-size:.75rem;color:var(--gray-mid)"><?= fmtTs((int)$ip['last_seen']) ?></td>
  </tr>
  <?php endforeach; ?>
  </tbody>
</table>

<!-- ── Журнал сесій ── -->
<div class="section-title" style="display:flex;justify-content:space-between;align-items:center">
  <span>📋 Журнал сесій</span>
  <span style="font-size:.78rem;color:var(--gray-mid);font-weight:400">Всього: <?= number_format($total) ?></span>
</div>

<!-- Фільтри -->
<form method="get" style="display:flex;flex-wrap:wrap;gap:8px;align-items:flex-end;margin-bottom:12px;padding:12px;background:#f8f9fa;border-radius:8px;border:1px solid var(--gray-border)">
  <?php if ($sid): ?><input type="hidden" name="sid" value="<?= $sid ?>"><?php endif; ?>
  <div>
    <div style="font-size:.7rem;color:var(--gray-mid);margin-bottom:3px">Користувач</div>
    <input class="form-input" name="user" value="<?= htmlspecialchars($filterUser) ?>" placeholder="ім'я..." style="width:130px">
  </div>
  <div>
    <div style="font-size:.7rem;color:var(--gray-mid);margin-bottom:3px">Протокол</div>
    <select class="form-select" name="proto" style="width:100px">
      <option value="all">Всі</option>
      <?php foreach ($allProtos as $p): ?>
      <option value="<?= htmlspecialchars($p) ?>" <?= $p===$filterProto?'selected':'' ?>><?= strtoupper(htmlspecialchars($p)) ?></option>
      <?php endforeach; ?>
    </select>
  </div>
  <div>
    <div style="font-size:.7rem;color:var(--gray-mid);margin-bottom:3px">З дати</div>
    <input class="form-input" type="date" name="from" value="<?= htmlspecialchars($filterFrom) ?>" style="width:130px">
  </div>
  <div>
    <div style="font-size:.7rem;color:var(--gray-mid);margin-bottom:3px">По дату</div>
    <input class="form-input" type="date" name="to" value="<?= htmlspecialchars($filterTo) ?>" style="width:130px">
  </div>
  <button type="submit" class="btn btn-primary" style="height:34px">🔍 Фільтр</button>
  <?php if ($filterUser || $filterProto || $filterFrom || $filterTo): ?>
  <a href="vpn.php<?= $sidQ ?>" class="btn btn-secondary" style="height:34px;line-height:22px">✕ Скинути</a>
  <?php endif; ?>
</form>

<table class="tbl">
  <thead><tr>
    <th>#</th><th>Користувач</th><th>Протокол</th><th>IP-адреса</th>
    <th>Підключення</th><th>Відключення</th><th>Тривалість</th><th>Інтерфейс</th>
  </tr></thead>
  <tbody>
  <?php if (empty($sessions)): ?>
  <tr><td colspan="8" class="no-data" style="padding:24px">Записів не знайдено</td></tr>
  <?php endif; ?>
  <?php foreach ($sessions as $i => $s):
    $isActive = ($s['disconnected_at'] === null && $s['connected_at'] !== null);
    $col = $protoColors[strtolower($s['protocol'])] ?? '#607D8B';
  ?>
  <tr <?= $isActive ? 'class="row-warn"' : '' ?>>
    <td style="color:#bbb;font-size:.7rem"><?= $offset+$i+1 ?></td>
    <td>
      <a href="vpn.php<?= $sidQ ?>&user=<?= urlencode($s['username']) ?>" style="color:var(--blue-main);font-weight:600">
        <?= htmlspecialchars($s['username']) ?>
      </a>
    </td>
    <td><span style="background:<?= $col ?>22;color:<?= $col ?>;padding:2px 7px;border-radius:8px;font-size:.7rem;font-weight:700"><?= strtoupper(htmlspecialchars($s['protocol'])) ?></span></td>
    <td style="font-family:monospace;font-size:.78rem"><?= htmlspecialchars($s['ip_address'] ?: '—') ?></td>
    <td style="font-size:.78rem;white-space:nowrap"><?= fmtTs($s['connected_at'] ? (int)$s['connected_at'] : null) ?></td>
    <td style="font-size:.78rem;white-space:nowrap">
      <?php if ($isActive): ?>
      <span class="badge badge-active">● активна</span>
      <?php else: ?>
      <?= fmtTs($s['disconnected_at'] ? (int)$s['disconnected_at'] : null) ?>
      <?php endif; ?>
    </td>
    <td style="font-size:.78rem;white-space:nowrap;font-weight:<?= ($s['duration_sec'] ?? 0) > 3600 ? 700 : 400 ?>"><?= fmtDur($s['duration_sec'] !== null ? (int)$s['duration_sec'] : null) ?></td>
    <td style="font-size:.72rem;color:var(--gray-light)"><?= htmlspecialchars($s['interface'] ?: '—') ?></td>
  </tr>
  <?php endforeach; ?>
  </tbody>
</table>

<!-- Пагінація -->
<?php if ($pages > 1): ?>
<div style="display:flex;gap:6px;justify-content:center;padding:16px 0">
  <?php
  $qBase = 'vpn.php?' . http_build_query(array_filter(['sid'=>$sid,'user'=>$filterUser,'proto'=>$filterProto,'from'=>$filterFrom,'to'=>$filterTo]));
  for ($p = max(1,$page-3); $p <= min($pages,$page+3); $p++): ?>
  <a href="<?= $qBase ?>&page=<?= $p ?>" class="btn <?= $p===$page?'btn-primary':'btn-secondary' ?>" style="min-width:36px;padding:4px 0;text-align:center"><?= $p ?></a>
  <?php endfor; ?>
</div>
<?php endif; ?>

<?php endif; ?>

<?php if (!empty($mailOk)): ?>
<div style="background:#dcfce7;border:1px solid #86efac;border-radius:8px;padding:12px 18px;margin:0 0 16px;color:#166534;font-size:.88rem">
  ✅ <?= htmlspecialchars($mailOk) ?>
</div>
<?php endif; ?>
<?php if (!empty($mailErr)): ?>
<div style="background:#fee2e2;border:1px solid #fca5a5;border-radius:8px;padding:12px 18px;margin:0 0 16px;color:#991b1b;font-size:.88rem">
  ❌ <?= htmlspecialchars($mailErr) ?>
</div>
<?php endif; ?>

<!-- ── Email Modal ──────────────────────────────────────────────────────── -->
<div id="email-modal" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,.45);z-index:1000;align-items:center;justify-content:center">
  <div style="background:var(--white);border-radius:12px;box-shadow:0 8px 40px rgba(0,0,0,.22);width:100%;max-width:480px;padding:28px 32px;position:relative">
    <button onclick="document.getElementById('email-modal').style.display='none'"
      style="position:absolute;top:14px;right:18px;background:none;border:none;font-size:1.4rem;cursor:pointer;color:var(--gray-mid)">×</button>
    <h3 style="margin:0 0 18px;font-size:1.05rem;color:var(--blue-dark)">📧 Надіслати VPN-звіт на пошту</h3>
    <form method="post">
      <input type="hidden" name="action" value="send_email">
      <input type="hidden" name="sid" value="<?= $sid ?>">
      <div style="display:grid;gap:12px">
        <label style="font-size:.83rem;font-weight:600;color:#444">
          Отримувач (email) *
          <input type="email" name="mail_to" required
            value="<?= htmlspecialchars($_POST['mail_to'] ?? '') ?>"
            placeholder="admin@example.com"
            style="display:block;width:100%;margin-top:4px;padding:8px 10px;border:1px solid #ccc;border-radius:6px;font-size:.88rem;box-sizing:border-box">
        </label>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px">
          <label style="font-size:.83rem;font-weight:600;color:#444">
            Дата від *
            <input type="date" name="mail_date_from" required
              value="<?= htmlspecialchars($_POST['mail_date_from'] ?? date('Y-m-d', strtotime('-7 days'))) ?>"
              style="display:block;width:100%;margin-top:4px;padding:8px 10px;border:1px solid #ccc;border-radius:6px;font-size:.88rem;box-sizing:border-box">
          </label>
          <label style="font-size:.83rem;font-weight:600;color:#444">
            Дата до *
            <input type="date" name="mail_date_to" required
              value="<?= htmlspecialchars($_POST['mail_date_to'] ?? date('Y-m-d')) ?>"
              style="display:block;width:100%;margin-top:4px;padding:8px 10px;border:1px solid #ccc;border-radius:6px;font-size:.88rem;box-sizing:border-box">
          </label>
        </div>
        <label style="font-size:.83rem;font-weight:600;color:#444">
          Відправник (необов'язково)
          <input type="email" name="mail_from"
            value="<?= htmlspecialchars($_POST['mail_from'] ?? '') ?>"
            placeholder="logportal@example.com (з налаштувань SMTP)"
            style="display:block;width:100%;margin-top:4px;padding:8px 10px;border:1px solid #ccc;border-radius:6px;font-size:.88rem;box-sizing:border-box">
        </label>
        <p style="margin:0;font-size:.78rem;color:var(--gray-mid)">
          SMTP-сервер налаштовується в розділі <a href="admin.php" style="color:#1a56db">Адмін → Налаштування</a>.
        </p>
        <div style="display:flex;gap:10px;justify-content:flex-end;margin-top:4px">
          <button type="button" onclick="document.getElementById('email-modal').style.display='none'"
            style="padding:8px 18px;border:1px solid #ccc;border-radius:6px;background:#f5f5f5;cursor:pointer;font-size:.85rem">Скасувати</button>
          <button type="submit"
            style="padding:8px 22px;background:#1F4E79;color:#fff;border:none;border-radius:6px;font-weight:600;cursor:pointer;font-size:.85rem">📤 Надіслати</button>
        </div>
      </div>
    </form>
  </div>
</div>
<script>
// Закриття по кліку на backdrop
document.getElementById('email-modal').addEventListener('click', function(e){
  if(e.target === this) this.style.display='none';
});
// Якщо є помилка/успіх — відкрити модалку автоматично щоб показати результат
<?php if (!empty($mailErr)): ?>
document.addEventListener('DOMContentLoaded', function(){
  document.getElementById('email-modal').style.display='flex';
});
<?php endif; ?>
</script>
</div></main>
<?php renderFooter(); ?>
</body>
</html>
