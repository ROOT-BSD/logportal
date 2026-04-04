<?php
require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/layout.php';
require_once __DIR__ . '/includes/ssh.php';
require_once __DIR__ . '/includes/nginx_parser.php';
require_once __DIR__ . '/includes/postfix_parser.php';
require_once __DIR__ . '/includes/bind_parser.php';
require_once __DIR__ . '/includes/mikrotik_parser.php';
require_once __DIR__ . '/includes/filters.php';
requireAuth();
$user = currentUser();
$db   = getDB();

$sid = (int)($_GET['sid'] ?? 0);
if (!$sid) { header('Location: servers.php'); exit; }

// Підтримка як одного файлу (старі посилання) так і масиву
$files = $_GET['files'] ?? [];
if (empty($files) && !empty($_GET['file'])) $files = [$_GET['file']];
$files = array_filter(array_map('trim', (array)$files));
if (empty($files)) { header("Location: logs.php?sid=$sid"); exit; }

// Фільтр по датах
$dateFrom = $_GET['date_from'] ?? '';
$dateTo   = $_GET['date_to']   ?? '';
$tsFrom   = $dateFrom ? strtotime($dateFrom . ' 00:00:00') : 0;
$tsTo     = $dateTo   ? strtotime($dateTo   . ' 23:59:59') : PHP_INT_MAX;

$st = $db->prepare("SELECT * FROM servers WHERE id=? AND user_id=?");
$st->execute([$sid, $user['id']]);
$srv = $st->fetch();
if (!$srv) { header('Location: servers.php'); exit; }

$conn  = sshConnect($srv);
$err   = '';
$stats = null;
$logType = 'nginx';
$parsedFiles = [];

if (!$conn['success']) {
    $err = $conn['error'] ?? 'Помилка підключення SSH';
    $db->prepare("UPDATE servers SET status='offline',last_check=CURRENT_TIMESTAMP WHERE id=?")->execute([$sid]);
} else {
    $allRaw = '';
    $fileErrors = [];
    $isMt = isMikrotik($srv);
    $mtDebugLines = [];

    if ($isMt) {
        // ── Mikrotik: читаємо через RouterOS CLI ──
        foreach ($files as $file) {
            if ($file === '__mikrotik_memory__') {
                $raw = readMikrotikLog($conn, 5000);
                $parsedFiles[] = 'RouterOS Memory Log';
            } else {
                $raw = readMikrotikFile($conn, $file);
                $parsedFiles[] = basename($file);
            }
            // Debug: перші рядки для діагностики
            if (empty($mtDebugLines)) {
                $allLines = array_filter(array_map('rtrim', explode("\n", (string)$raw)));
                $mtDebugLines = array_values(array_slice($allLines, 0, 12));
            }
            if (!empty(trim((string)$raw))) {
                $allRaw .= $raw . "\n";
            }
        }
        // Якщо allRaw порожній — показуємо raw вивід /log print для діагностики
        if (empty(trim($allRaw))) {
            $rawDebug = sshExecMikrotik($conn, '/log print');
            if (empty($mtDebugLines) && !empty(trim($rawDebug))) {
                $allLines = array_filter(array_map('rtrim', explode("\n", $rawDebug)));
                $mtDebugLines = array_values(array_slice($allLines, 0, 15));
            }
            $err = "Mikrotik: /log print повернув порожній результат. Перевірте права користувача (потрібно: read).";
        }
    } else {
        // ── Linux: стандартне читання через bash ──
        foreach ($files as $file) {
            $isGz = str_ends_with(strtolower($file), '.gz');
            if ($isGz) {
                $zcatBin = trim(sshExec($conn, 'which zcat 2>/dev/null || which gzip 2>/dev/null'));
                if (empty($zcatBin)) { $fileErrors[] = "zcat не знайдено для: " . basename($file); continue; }
                $zcmd = str_ends_with($zcatBin, 'gzip') ? 'gzip -dc' : 'zcat';
                $raw  = sshExec($conn, "$zcmd " . escapeshellarg($file) . " 2>/dev/null");
            } else {
                $sz  = (int)trim(sshExec($conn, "wc -c " . escapeshellarg($file) . " 2>/dev/null | awk '{print \$1}'"));
                $hasDateFilter = ($tsFrom > 0 || $tsTo < PHP_INT_MAX);
                if ($sz > 209715200 && !$hasDateFilter) {
                    $raw = sshExec($conn, "tail -n 2000000 " . escapeshellarg($file) . " 2>/dev/null");
                } else {
                    $raw = sshExec($conn, "cat " . escapeshellarg($file) . " 2>/dev/null");
                }
            }
            if (empty(trim($raw))) { $fileErrors[] = "Порожній або недоступний: " . basename($file); continue; }
            $allRaw .= $raw . "\n";
            $parsedFiles[] = basename($file);
            unset($raw);
        }
        if ($fileErrors && empty($parsedFiles)) $err = implode('; ', $fileErrors);
        elseif (empty(trim($allRaw)))           $err = "Усі вибрані файли порожні або недоступні";
    }

    if (!$err && !empty(trim($allRaw))) {
        // Для Mikrotik тип завжди mikrotik; для інших — авто-детект
        $logType  = $isMt ? 'mikrotik' : detectLogType($allRaw);
        $hintYear = 0;
        foreach ($files as $file) {
            if (preg_match('~/(\d{4})/~', $file, $ym)) {
                $y = (int)$ym[1];
                if ($y >= 2000 && $y <= 2099) { $hintYear = $y; break; }
            }
        }
        if (!$isMt && ($tsFrom > 0 || $tsTo < PHP_INT_MAX)) {
            $allRaw = filterByDate($allRaw, $logType, $tsFrom, $tsTo, $hintYear);
        }
        if ($logType === 'postfix') {
            $stats = parsePostfixLog($allRaw, 5000000, $hintYear);
        } elseif ($logType === 'bind') {
            $stats = parseBindLog($allRaw);
        } elseif ($logType === 'mikrotik') {
            $stats = parseMikrotikLog($allRaw);
            // ── Зберігаємо VPN сесії в БД ──
            if (!empty($stats['vpn_sessions'])) {
                // Видаляємо старі записи цього сервера за той самий період
                // щоб повторний аналіз оновив дані (зокрема IP адреси)
                $tMin = PHP_INT_MAX; $tMax = 0;
                foreach ($stats['vpn_sessions'] as $vs) {
                    if ($vs['ts_con']) { $tMin = min($tMin, $vs['ts_con']); $tMax = max($tMax, $vs['ts_con']); }
                    if ($vs['ts_dis']) { $tMin = min($tMin, $vs['ts_dis']); $tMax = max($tMax, $vs['ts_dis']); }
                }
                if ($tMin < PHP_INT_MAX) {
                    $db->prepare("DELETE FROM vpn_sessions WHERE server_id=? AND connected_at>=? AND connected_at<=?")
                       ->execute([$sid, $tMin, $tMax]);
                }

                $stmtVpn = $db->prepare(
                    "INSERT INTO vpn_sessions
                        (server_id, username, protocol, ip_address, connected_at, disconnected_at, duration_sec, interface)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
                );
                $insertNow = time();
                foreach ($stats['vpn_sessions'] as $vs) {
                    if (empty($vs['user'])) continue;
                    if (empty($vs['ts_con'])) continue;
                    // Активна сесія не може тривати більше 24 годин
                    if (empty($vs['ts_dis']) && ($insertNow - $vs['ts_con']) > 86400) continue;
                    $stmtVpn->execute([
                        $sid,
                        $vs['user'],
                        $vs['proto'] ?? 'unknown',
                        $vs['ip']    ?? '',
                        $vs['ts_con'],
                        $vs['ts_dis'],
                        $vs['duration'],
                        $vs['iface'] ?? '',
                    ]);
                }
            } // end if vpn_sessions
        } else {
            $stats = parseNginxLog($allRaw);
        }
        unset($allRaw);
        $totalRec = $stats['total_lines'] ?? $stats['total'] ?? 0;
        $db->prepare("INSERT INTO log_sessions(server_id,log_file,total_requests) VALUES(?,?,?)")
           ->execute([$sid, implode(', ', $parsedFiles), $totalRec]);
    }
}


// ── Хелпери шаблону ──
function pct(int $n, int $t): string { return $t>0 ? round($n/$t*100,1).'%' : '0%'; }
function bar(int $v, int $max, string $clr='var(--blue-main),var(--blue-light)'): string {
    $w = $max>0 ? min(100,(int)round($v/$max*100)) : 0;
    return "<div class='prog-track'><div class='prog-fill' style='width:{$w}%;background:linear-gradient(90deg,{$clr})'>"
         . "<span class='prog-val'>".number_format($v)."</span></div></div>";
}
?>
<!DOCTYPE html>
<html lang="uk">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Аналіз: <?= htmlspecialchars(implode(', ', array_map('basename', $files))) ?> — LogPortal</title>
<link rel="stylesheet" href="css/style.css">
<script>
(function(){var t=localStorage.getItem('lp_theme');if(t)document.documentElement.setAttribute('data-theme',t);})();
</script>
</head>
<body>
<div class="page-wrap">

<?php renderGovStrip(); renderHeader($user); renderNav($user, 'logs', $sid); ?>
<div class="breadcrumbs"><div class="container">
  <a href="servers.php">Сервери</a><span class="bc-sep">›</span>
  <a href="logs.php?sid=<?= $sid ?>"><?= htmlspecialchars($srv['name']) ?></a><span class="bc-sep">›</span>
  <span class="bc-current">Аналіз</span>
</div></div>

<main class="page-content"><div class="container">

<div class="page-title-block">
  <div class="page-title-text">
    <h1>📊 Аналіз <?= $logType==='postfix' ? 'Postfix' : ($logType==='bind' ? 'BIND' : ($logType==='mikrotik' ? 'Mikrotik' : 'Nginx')) ?> журналів</h1>
    <div style="margin-top:6px">
      <div class="files-list">
        <?php foreach ($parsedFiles ?: array_map('basename',$files) as $fn): ?>
          <span class="file-chip">📄 <?= htmlspecialchars($fn) ?></span>
        <?php endforeach; ?>
        <?php if ($dateFrom || $dateTo): ?>
          <span class="date-chip">📅 <?= $dateFrom ?: '…' ?> — <?= $dateTo ?: 'сьогодні' ?></span>
        <?php endif; ?>
      </div>
    </div>
  </div>
  <div class="flex gap-2">
    <a href="logs.php?sid=<?= $sid ?>" class="btn btn-outline btn-sm">← Назад</a>
    <a href="<?= htmlspecialchars($_SERVER['REQUEST_URI']) ?>" class="btn btn-primary btn-sm">🔄 Оновити</a>
    <?php if ($isMt ?? false): ?>
    <a href="address_list.php?sid=<?= $sid ?>" class="btn btn-sm" style="background:#e65100;color:#fff;border:none">📋 Address List</a>
    <?php endif; ?>
    <button onclick="saveReport()" class="btn btn-sm" style="background:#2e7d32;color:#fff;border:none;cursor:pointer" title="Зберегти як автономний HTML файл">💾 Зберегти звіт</button>
  </div>
</div>

<?php if ($err): ?>
  <div class="alert alert-error">
    <span class="alert-icon">✕</span>
    <div><strong>Помилка</strong><br><?= htmlspecialchars($err) ?></div>
  </div>
<?php endif; ?>

<?php if (!$err && $stats !== null && ($stats['total_lines'] ?? $stats['total'] ?? 0) === 0): ?>
  <div class="alert alert-warning">
    <span class="alert-icon">⚠</span>
    <?php if ($dateFrom || $dateTo): ?>
      За вибраний період <strong><?= $dateFrom ?: '…' ?> — <?= $dateTo ?: '…' ?></strong> записів не знайдено.
    <?php else: ?>
      Файли не містять записів у відомому форматі.
    <?php endif; ?>
  </div>
  <?php if ($logType === 'mikrotik'): ?>
  <div class="card" style="border-left:4px solid var(--orange-warn);margin-bottom:16px">
    <div class="card-header" style="background:#fff8f0">
      <div class="card-header-title" style="color:var(--orange-warn)">🔍 Вивід RouterOS (діагностика)</div>
    </div>
    <div class="card-body">
      <?php if (!empty($mtDebugLines)): ?>
      <pre style="background:#1a1a2e;color:#00d4aa;padding:12px;border-radius:4px;font-size:.72rem;overflow-x:auto;white-space:pre-wrap"><?= htmlspecialchars(implode("\n", $mtDebugLines)) ?></pre>
      <?php else: ?>
      <div style="background:#1a1a2e;color:#ff6b6b;padding:12px;border-radius:4px;font-size:.72rem">/log print повернув порожній рядок</div>
      <?php endif; ?>
      <div style="font-size:.75rem;color:var(--gray-mid);margin-top:12px">
        <strong>Підтримувані формати:</strong><br>
        &bull; <code>mar/09/2026 14:23:01 firewall,info ...</code><br>
        &bull; <code>mar/09 14:23:01 firewall,info ...</code><br>
        &bull; <code>14:23:01 firewall,info ...</code><br>
        &bull; <code>2026-03-09 14:23:01 router firewall,info ...</code>
        <div style="margin-top:10px;padding:8px 12px;background:#fff3e0;border-radius:6px;color:#7c4400">
          <strong>Якщо бачите помилку RouterOS вище:</strong> команда передається неправильно.<br>
          Спробуйте в RouterOS Terminal вручну: <code>/log print</code>
        </div>
      </div>
    </div>
  </div>
  <?php endif; ?>
<?php endif; ?>

<?php if (!$err && $stats !== null && ($stats['total_lines'] ?? $stats['total'] ?? 0) > 0):
$s = $stats; ?>

<?php if (($s['type'] ?? '') === 'postfix'): ?>
<?php
  $pfHours = $s['hours'];
  $pfMaxHr = max($pfHours) ?: 1;
  $pfTotal = $s['msg_total'];
?>
<!-- ═══ POSTFIX STAT CARDS ═══ -->
<div class="stats-row">
  <div class="stat-card">
    <div class="stat-label">Рядків лога</div>
    <div class="stat-value"><?= number_format($s['total_lines']) ?></div>
    <div class="stat-sub">
      <?= $s['ts_start'] ? date('d.m.Y',$s['ts_start']) : '' ?>
      <?= ($s['ts_start']&&$s['ts_end']) ? ' – '.date('d.m.Y',$s['ts_end']) : '' ?>
    </div>
  </div>
  <div class="stat-card green">
    <div class="stat-label">Доставлено</div>
    <div class="stat-value" style="color:var(--green-ok)"><?= number_format($s['sent']) ?></div>
    <div class="stat-sub"><?= $pfTotal>0 ? round($s['sent']/$pfTotal*100,1).'%' : '—' ?> від усіх</div>
  </div>
  <div class="stat-card red">
    <div class="stat-label">Відхилено</div>
    <div class="stat-value" style="color:var(--red-err)"><?= number_format($s['rejected']) ?></div>
    <div class="stat-sub">reject / NOQUEUE</div>
  </div>
  <div class="stat-card orange">
    <div class="stat-label">Відкладено</div>
    <div class="stat-value" style="color:var(--orange-warn)"><?= number_format($s['deferred']) ?></div>
    <div class="stat-sub">deferred</div>
  </div>
  <div class="stat-card" style="border-top-color:#8B0000">
    <div class="stat-label">Повернуто</div>
    <div class="stat-value" style="color:#8B0000"><?= number_format($s['bounced']) ?></div>
    <div class="stat-sub">bounce / NDR</div>
  </div>
  <div class="stat-card">
    <div class="stat-label">Підключення</div>
    <div class="stat-value"><?= number_format($s['connects']) ?></div>
    <div class="stat-sub">SMTP connect</div>
  </div>
  <div class="stat-card yellow">
    <div class="stat-label">Обсяг пошти</div>
    <div class="stat-value" style="font-size:1.1rem"><?= fmtBytes($s['total_size']) ?></div>
    <div class="stat-sub">Затримка макс: <?= $s['max_delay'] ?>с</div>
  </div>
  <div class="stat-card">
    <div class="stat-label">Унікальних відправників</div>
    <div class="stat-value"><?= number_format($s['unique_senders']) ?></div>
    <div class="stat-sub">Одержувачів: <?= number_format($s['unique_rcpt']) ?></div>
  </div>
</div>

<!-- ═══ POSTFIX: Розбивка по датах ═══ -->
<?php if (!empty($s['days'])): ?>
<div class="mb-4"><div class="card">
  <div class="card-header"><div class="card-header-title"><div class="section-head-icon">📅</div> Активність по датах</div></div>
  <div class="card-body" style="padding:0">
    <div style="overflow-x:auto;max-height:340px;overflow-y:auto">
    <table class="date-table">
      <thead><tr><th>Дата</th><th>Рядків</th><th>Розподіл</th></tr></thead>
      <tbody>
      <?php
        $maxDay = max($s['days']);
        foreach ($s['days'] as $dk => $cnt):
          $w = $maxDay>0 ? max(4,round($cnt/$maxDay*200)) : 4;
          $dt = DateTime::createFromFormat('Y-m-d', $dk);
          $label = $dt ? $dt->format('d.m.Y') . ' (' . ['Нд','Пн','Вт','Ср','Чт','Пт','Сб'][(int)$dt->format('w')] . ')' : $dk;
      ?>
      <tr>
        <td style="font-family:var(--font-mono)"><?= $label ?></td>
        <td class="num"><?= number_format($cnt) ?></td>
        <td><span class="date-bar" style="width:<?= $w ?>px"></span></td>
      </tr>
      <?php endforeach; ?>
      </tbody>
    </table>
    </div>
  </div>
</div></div>
<?php endif; ?>

<!-- ═══ POSTFIX: Активність по годинах ═══ -->
<div class="mb-4"><div class="card">
  <div class="card-header"><div class="card-header-title"><div class="section-head-icon">⏰</div> Активність по годинах</div></div>
  <div class="card-body">
    <div class="hour-chart">
      <?php for ($h=0;$h<24;$h++):
        $cnt=$pfHours[$h]; $ht=$pfMaxHr>0?max(2,(int)round($cnt/$pfMaxHr*100)):2; ?>
        <div class="hour-bar" style="height:<?= $ht ?>%">
          <div class="hour-bar-tip"><?= sprintf('%02d:00',$h) ?> — <?= number_format($cnt) ?></div>
        </div>
      <?php endfor; ?>
    </div>
    <div style="display:flex;justify-content:space-between;font-size:.65rem;color:var(--gray-light);margin-top:4px;padding:0 4px">
      <span>00</span><span>06</span><span>12</span><span>18</span><span>23</span>
    </div>
  </div>
</div></div>

<!-- ═══ POSTFIX: Статистика + Демони ═══ -->
<div class="grid-2 mb-4">
  <div class="card">
    <div class="card-header"><div class="card-header-title"><div class="section-head-icon">📊</div> Стан повідомлень</div></div>
    <div class="card-body">
      <?php $pfStatuses=['sent'=>['Доставлено','var(--green-ok),#388e3c'],'deferred'=>['Відкладено','var(--orange-warn),#f57c00'],'bounced'=>['Повернуто','#8B0000,#c0392b'],'expired'=>['Прострочено','var(--gray-light),#9e9e9e']];
      $pfMax=$pfTotal>0?$pfTotal:1;
      foreach ($pfStatuses as $key=>[$label,$clr]):
        $cnt=$s[$key]; if (!$cnt) continue; ?>
      <div class="prog-wrap">
        <div class="prog-label" style="min-width:110px"><?= $label ?></div>
        <?= bar($cnt,$pfMax,$clr) ?>
        <div class="prog-count"><?= $pfTotal>0?round($cnt/$pfTotal*100,1).'%':'—' ?></div>
      </div>
      <?php endforeach; ?>
    </div>
  </div>
  <div class="card">
    <div class="card-header"><div class="card-header-title"><div class="section-head-icon">⚙</div> Postfix демони</div></div>
    <div class="card-body">
      <?php if ($s['daemons']): $maxD=max($s['daemons']);
      foreach ($s['daemons'] as $d=>$cnt): ?>
      <div class="prog-wrap">
        <div class="prog-label" style="min-width:140px;font-family:var(--font-mono)"><?= htmlspecialchars($d) ?></div>
        <?= bar($cnt,$maxD) ?>
      </div>
      <?php endforeach; endif; ?>
    </div>
  </div>
</div>

<!-- ═══ POSTFIX: Відхилення ═══ -->
<?php if ($s['rejected']>0): ?>
<div class="grid-2 mb-4">
  <div class="card" style="border-top:3px solid var(--red-err)">
    <div class="card-header" style="background:#fdf0f0;border-bottom-color:#f5c6c6">
      <div class="card-header-title" style="color:var(--red-err)">
        <div class="section-head-icon" style="background:var(--red-err)">✕</div>
        Причини відхилень (<?= number_format($s['rejected']) ?>)
      </div>
    </div>
    <div class="card-body">
      <?php if ($s['reject_reasons']): $maxR=max($s['reject_reasons']);
      foreach ($s['reject_reasons'] as $reason=>$cnt): ?>
      <div class="prog-wrap">
        <div class="prog-label" style="min-width:200px;font-size:.72rem" title="<?= htmlspecialchars($reason) ?>"><?= htmlspecialchars(substr($reason,0,40)) ?></div>
        <?= bar($cnt,$maxR,'var(--red-err),#e53935') ?>
      </div>
      <?php endforeach; endif; ?>
    </div>
  </div>
  <div class="card" style="border-top:3px solid var(--red-err)">
    <div class="card-header" style="background:#fdf0f0;border-bottom-color:#f5c6c6">
      <div class="card-header-title" style="color:var(--red-err)">
        <div class="section-head-icon" style="background:var(--red-err)">🌐</div>
        IP що відхилено
      </div>
    </div>
    <div class="card-body">
      <?php if ($s['reject_ips']): $maxRi=max($s['reject_ips']);
      foreach ($s['reject_ips'] as $ip=>$cnt): ?>
      <div class="prog-wrap">
        <div class="prog-label"><?= htmlspecialchars($ip) ?></div>
        <?= bar($cnt,$maxRi,'var(--red-err),#e53935') ?>
      </div>
      <?php endforeach; endif; ?>
    </div>
  </div>
</div>
<?php if ($s['reject_from']): ?>
<div class="mb-4"><div class="card" style="border-top:3px solid var(--red-err)">
  <div class="card-header" style="background:#fdf0f0;border-bottom-color:#f5c6c6">
    <div class="card-header-title" style="color:var(--red-err)">
      <div class="section-head-icon" style="background:var(--red-err)">✉</div>
      Відправники яких відхилено
    </div>
  </div>
  <div class="card-body">
    <?php $maxRf=max($s['reject_from']);
    foreach ($s['reject_from'] as $addr=>$cnt): ?>
    <div class="prog-wrap">
      <div class="prog-label" style="font-family:var(--font-mono);font-size:.78rem" title="<?= htmlspecialchars($addr) ?>"><?= htmlspecialchars(substr($addr,0,40)) ?></div>
      <?= bar($cnt,$maxRf,'var(--red-err),#e53935') ?>
    </div>
    <?php endforeach; ?>
  </div>
</div></div>
<?php endif; ?>
<?php endif; /* rejected */ ?>

<!-- ═══ POSTFIX: Топ відправники / одержувачі / relay ═══ -->
<div class="grid-2 mb-4">
  <div class="card">
    <div class="card-header"><div class="card-header-title"><div class="section-head-icon">📤</div> Топ відправники (from)</div></div>
    <div class="card-body">
      <?php if ($s['top_from']): $maxF=max($s['top_from']);
      foreach ($s['top_from'] as $addr=>$cnt): ?>
      <div class="prog-wrap">
        <div class="prog-label" style="font-family:var(--font-mono);font-size:.75rem" title="<?= htmlspecialchars($addr) ?>"><?= htmlspecialchars(substr($addr,0,35)) ?></div>
        <?= bar($cnt,$maxF) ?>
      </div>
      <?php endforeach;
      else: ?><p style="color:var(--gray-light);font-size:.8rem;text-align:center;padding:16px">Даних немає</p><?php endif; ?>
    </div>
  </div>
  <div class="card">
    <div class="card-header"><div class="card-header-title"><div class="section-head-icon">📥</div> Топ одержувачі (to)</div></div>
    <div class="card-body">
      <?php if ($s['top_to']): $maxT=max($s['top_to']);
      foreach ($s['top_to'] as $addr=>$cnt): ?>
      <div class="prog-wrap">
        <div class="prog-label" style="font-family:var(--font-mono);font-size:.75rem" title="<?= htmlspecialchars($addr) ?>"><?= htmlspecialchars(substr($addr,0,35)) ?></div>
        <?= bar($cnt,$maxT) ?>
      </div>
      <?php endforeach;
      else: ?><p style="color:var(--gray-light);font-size:.8rem;text-align:center;padding:16px">Даних немає</p><?php endif; ?>
    </div>
  </div>
</div>

<?php if ($s['top_relays']): ?>
<div class="mb-4"><div class="card">
  <div class="card-header"><div class="card-header-title"><div class="section-head-icon">🔀</div> Топ relay-хости</div></div>
  <div class="card-body">
    <?php $maxRl=max($s['top_relays']);
    foreach ($s['top_relays'] as $relay=>$cnt): ?>
    <div class="prog-wrap">
      <div class="prog-label" style="font-family:var(--font-mono);font-size:.78rem"><?= htmlspecialchars($relay) ?></div>
      <?= bar($cnt,$maxRl) ?>
    </div>
    <?php endforeach; ?>
  </div>
</div></div>
<?php endif; ?>

<?php if ($s['parse_errors'] > 0): ?>
<div class="alert alert-warning">
  <span class="alert-icon">⚠</span>
  <strong><?= number_format($s['parse_errors']) ?> рядків</strong> пропущено (не формат Postfix syslog).
</div>
<?php endif; ?>

<?php if (!empty($s['messages'])): ?>
<div class="alert" style="background:var(--green-light);border-left:4px solid var(--green-ok);display:flex;align-items:center;justify-content:space-between;gap:16px">
  <span>✉ Знайдено <strong><?= number_format(count($s['messages'])) ?></strong> повідомлень у черзі Postfix</span>
  <a href="mail_search.php?sid=<?= $sid ?>&<?= htmlspecialchars(http_build_query(['files' => $files, 'date_from' => $dateFrom, 'date_to' => $dateTo])) ?>"
     class="btn btn-sm" style="background:var(--green-ok);color:#fff;border:none;white-space:nowrap">
    🔍 Пошук повідомлень →
  </a>
</div>
<?php endif; ?>

<?php elseif (($s['type'] ?? '') === 'nginx'): /* NGINX */
$total = $s['total'];
$maxIp = $s['top_ips'] ? max($s['top_ips']) : 1;
$maxHr = max($s['hours']); ?>

<!-- ═══ NGINX STAT CARDS ═══ -->
<div class="stats-row">
  <div class="stat-card">
    <div class="stat-label">Всього запитів</div>
    <div class="stat-value"><?= number_format($total) ?></div>
    <div class="stat-sub">
      <?= $s['ts_start'] ? date('d.m.Y',$s['ts_start']) : '' ?>
      <?= ($s['ts_start']&&$s['ts_end']) ? ' – '.date('d.m.Y',$s['ts_end']) : '' ?>
    </div>
  </div>
  <div class="stat-card green">
    <div class="stat-label">Успішні (2xx)</div>
    <div class="stat-value" style="color:var(--green-ok)"><?= number_format($s['status_groups']['2xx']) ?></div>
    <div class="stat-sub"><?= pct($s['status_groups']['2xx'],$total) ?> від усіх</div>
  </div>
  <div class="stat-card red">
    <div class="stat-label">Рівень помилок</div>
    <div class="stat-value" style="color:var(--red-err)"><?= $s['error_rate'] ?>%</div>
    <div class="stat-sub">4xx: <?= number_format($s['status_groups']['4xx']) ?> · 5xx: <?= number_format($s['status_groups']['5xx']) ?></div>
  </div>
  <div class="stat-card">
    <div class="stat-label">Унікальні IP</div>
    <div class="stat-value"><?= number_format($s['unique_ips']) ?></div>
    <div class="stat-sub">Боти: <?= number_format($s['bots']) ?></div>
  </div>
  <div class="stat-card yellow">
    <div class="stat-label">Трафік</div>
    <div class="stat-value" style="font-size:1.2rem"><?= fmtBytes($s['total_bytes']) ?></div>
    <div class="stat-sub">Середній: <?= fmtBytes($s['avg_bytes']) ?>/запит</div>
  </div>
  <div class="stat-card orange">
    <div class="stat-label">Пікова година</div>
    <div class="stat-value" style="color:var(--orange-warn)"><?= sprintf('%02d:00',$s['peak_hour']) ?></div>
    <div class="stat-sub"><?= number_format($s['hours'][$s['peak_hour']]) ?> запитів</div>
  </div>
  <div class="stat-card" style="border-top-color:#8B0000">
    <div class="stat-label">SQLi атаки</div>
    <div class="stat-value" style="color:#8B0000"><?= number_format($s['sqli_total']) ?></div>
    <div class="stat-sub"><?= count($s['sqli_by_ip']) ?> унікальних IP</div>
  </div>
  <div class="stat-card" style="border-top-color:#b5460f">
    <div class="stat-label">XSS атаки</div>
    <div class="stat-value" style="color:#b5460f"><?= number_format($s['xss_total']) ?></div>
    <div class="stat-sub"><?= count($s['xss_by_ip']) ?> унікальних IP</div>
  </div>
</div>

<!-- ═══ NGINX: Розбивка по датах ═══ -->
<?php if (!empty($s['dates'])): ?>
<div class="mb-4"><div class="card">
  <div class="card-header"><div class="card-header-title"><div class="section-head-icon">📅</div> Запити по датах</div></div>
  <div class="card-body" style="padding:0">
    <div style="overflow-x:auto;max-height:340px;overflow-y:auto">
    <table class="date-table">
      <thead><tr><th>Дата</th><th>Запитів</th><th>2xx</th><th>4xx</th><th>5xx</th><th>Розподіл</th></tr></thead>
      <tbody>
      <?php
        // Для nginx розбивка по датах з парсера (масив dates)
        $maxDayNg = $s['dates'] ? max($s['dates']) : 1;
        foreach ($s['dates'] as $dk=>$cnt):
          $w = $maxDayNg>0 ? max(4,round($cnt/$maxDayNg*200)) : 4;
          $dt = DateTime::createFromFormat('Y-m-d',$dk);
          $dow = $dt ? ['Нд','Пн','Вт','Ср','Чт','Пт','Сб'][(int)$dt->format('w')] : '';
          $label = $dt ? $dt->format('d.m.Y')." ($dow)" : $dk;
      ?>
      <tr>
        <td style="font-family:var(--font-mono)"><?= $label ?></td>
        <td class="num"><?= number_format($cnt) ?></td>
        <td class="num" style="color:var(--green-ok)">—</td>
        <td class="num" style="color:var(--orange-warn)">—</td>
        <td class="num" style="color:var(--red-err)">—</td>
        <td><span class="date-bar" style="width:<?= $w ?>px"></span></td>
      </tr>
      <?php endforeach; ?>
      </tbody>
    </table>
    </div>
  </div>
</div></div>
<?php endif; ?>

<!-- ═══ NGINX: Статуси + Методи + Годинник ═══ -->
<div class="grid-2 mb-4">
  <div class="card">
    <div class="card-header"><div class="card-header-title"><div class="section-head-icon">📈</div> HTTP Статус-коди</div></div>
    <div class="card-body">
      <div style="display:flex;gap:8px;margin-bottom:18px;flex-wrap:wrap">
        <?php foreach (['2xx'=>'badge-2xx','3xx'=>'badge-3xx','4xx'=>'badge-4xx','5xx'=>'badge-5xx'] as $g=>$cls):
          $cnt=$s['status_groups'][$g]; if (!$cnt) continue; ?>
          <div style="text-align:center;padding:10px 16px;background:var(--gray-bg);border-radius:var(--radius);border:1px solid var(--gray-border)">
            <div class="badge <?= $cls ?>" style="font-size:.75rem;margin-bottom:4px"><?= $g ?></div>
            <div style="font-size:1.1rem;font-weight:700"><?= number_format($cnt) ?></div>
            <div style="font-size:.7rem;color:var(--gray-light)"><?= pct($cnt,$total) ?></div>
          </div>
        <?php endforeach; ?>
      </div>
      <div style="overflow-x:auto"><table class="data-table">
        <thead><tr><th>Код</th><th>К-сть</th><th>%</th></tr></thead>
        <tbody>
          <?php foreach (array_slice($s['statuses'],0,12,true) as $code=>$cnt): ?>
          <tr><td><?= statusBadge((int)$code) ?></td><td class="num"><?= number_format($cnt) ?></td><td class="num"><?= pct($cnt,$total) ?></td></tr>
          <?php endforeach; ?>
        </tbody>
      </table></div>
    </div>
  </div>
  <div style="display:flex;flex-direction:column;gap:16px">
    <div class="card">
      <div class="card-header"><div class="card-header-title"><div class="section-head-icon">⚙</div> HTTP Методи</div></div>
      <div class="card-body">
        <?php $maxM=$s['methods']?max($s['methods']):1; arsort($s['methods']);
        foreach ($s['methods'] as $m=>$cnt): ?>
        <div class="prog-wrap">
          <div class="prog-label" style="min-width:60px"><?= htmlspecialchars($m) ?></div>
          <?= bar($cnt,$maxM) ?>
          <div class="prog-count"><?= pct($cnt,$total) ?></div>
        </div>
        <?php endforeach; ?>
      </div>
    </div>
    <div class="card">
      <div class="card-header"><div class="card-header-title"><div class="section-head-icon">⏰</div> Запити по годинах</div></div>
      <div class="card-body">
        <div class="hour-chart">
          <?php for ($h=0;$h<24;$h++):
            $cnt=$s['hours'][$h]; $ht=$maxHr>0?max(2,(int)round($cnt/$maxHr*100)):2; ?>
            <div class="hour-bar" style="height:<?= $ht ?>%">
              <div class="hour-bar-tip"><?= sprintf('%02d:00',$h) ?> — <?= number_format($cnt) ?></div>
            </div>
          <?php endfor; ?>
        </div>
        <div style="display:flex;justify-content:space-between;font-size:.65rem;color:var(--gray-light);margin-top:4px;padding:0 4px">
          <span>00</span><span>06</span><span>12</span><span>18</span><span>23</span>
        </div>
      </div>
    </div>
  </div>
</div>

<!-- ═══ NGINX: Топ IP ═══ -->
<div class="mb-4"><div class="card">
  <div class="card-header"><div class="card-header-title"><div class="section-head-icon">🌐</div> Топ IP-адреси (20)</div></div>
  <div class="card-body" style="padding:12px">
    <?php foreach ($s['top_ips'] as $ip=>$cnt): ?>
    <div class="prog-wrap">
      <div class="prog-label"><?= htmlspecialchars($ip) ?></div>
      <?= bar($cnt,$maxIp) ?>
      <div class="prog-count"><?= number_format($cnt) ?></div>
    </div>
    <?php endforeach; ?>
  </div>
</div></div>

<!-- ═══ NGINX: Трафік + 404 ═══ -->
<div class="grid-2 mb-4">
  <div class="card">
    <div class="card-header"><div class="card-header-title"><div class="section-head-icon">📦</div> Трафік по IP</div></div>
    <div class="card-body"><div style="overflow-x:auto"><table class="data-table">
      <thead><tr><th>#</th><th>IP</th><th>Байти</th></tr></thead>
      <tbody>
        <?php $i=1; foreach ($s['bw_by_ip'] as $ip=>$b): ?>
        <tr><td class="num" style="color:var(--gray-light)"><?= $i++ ?></td><td class="mono"><?= htmlspecialchars($ip) ?></td><td class="num"><?= fmtBytes($b) ?></td></tr>
        <?php endforeach; ?>
      </tbody>
    </table></div></div>
  </div>
  <div class="card">
    <div class="card-header"><div class="card-header-title"><div class="section-head-icon" style="background:var(--orange-warn)">404</div> Найчастіші 404</div></div>
    <div class="card-body">
      <?php if (empty($s['top_404'])): ?>
        <p style="color:var(--gray-light);font-size:.8rem;text-align:center;padding:16px">Помилок 404 не знайдено</p>
      <?php else:
        $mx404=max($s['top_404']);
        foreach ($s['top_404'] as $url=>$cnt): ?>
        <div class="prog-wrap">
          <div class="prog-label" title="<?= htmlspecialchars($url) ?>"><?= htmlspecialchars(substr($url,0,35)) ?></div>
          <?= bar($cnt,$mx404,'var(--orange-warn),#ff8f00') ?>
          <div class="prog-count"><?= number_format($cnt) ?></div>
        </div>
        <?php endforeach;
      endif; ?>
    </div>
  </div>
</div>

<!-- ═══ NGINX: SQLi + XSS ═══ -->
<?php if ($s['sqli_total']>0||$s['xss_total']>0): ?>
<div class="grid-2 mb-4">
  <div class="card" style="border-top:3px solid #8B0000">
    <div class="card-header" style="background:#fdf0f0;border-bottom-color:#f5c6c6">
      <div class="card-header-title" style="color:#8B0000">
        <div class="section-head-icon" style="background:#8B0000">💉</div>
        SQL Injection — <?= number_format($s['sqli_total']) ?>
      </div>
    </div>
    <div class="card-body" style="padding:14px">
      <?php if ($s['sqli_types']): $mx=max($s['sqli_types']); ?>
        <div class="sec-label">Типи атак</div>
        <?php foreach ($s['sqli_types'] as $t=>$c): ?>
        <div class="prog-wrap">
          <div class="prog-label" style="min-width:200px" title="<?= htmlspecialchars($t) ?>"><?= htmlspecialchars(substr($t,0,32)) ?></div>
          <?= bar($c,$mx,'#8B0000,#c0392b') ?>
        </div>
        <?php endforeach; endif; ?>
      <?php if ($s['sqli_by_ip']): $mx=max($s['sqli_by_ip']); ?>
        <div class="sec-label">Топ атакуючих IP</div>
        <?php foreach (array_slice($s['sqli_by_ip'],0,10,true) as $ip=>$c): ?>
        <div class="prog-wrap">
          <div class="prog-label"><?= htmlspecialchars($ip) ?></div>
          <?= bar($c,$mx,'#8B0000,#c0392b') ?>
        </div>
        <?php endforeach; endif; ?>
      <?php if ($s['sqli_hits']): ?>
        <div class="sec-label">Останні запити</div>
        <div class="attack-hits"><table class="data-table">
          <thead><tr><th>IP</th><th>M</th><th>URL</th><th>Тип</th><th>St</th></tr></thead>
          <tbody>
            <?php foreach ($s['sqli_hits'] as [$ip,$time,$method,$uri,$status,$type]): ?>
            <tr>
              <td class="mono"><?= htmlspecialchars($ip) ?></td>
              <td><span class="badge badge-info"><?= htmlspecialchars($method) ?></span></td>
              <td class="mono" style="font-size:.72rem;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="<?= htmlspecialchars($uri) ?>"><?= htmlspecialchars(substr($uri,0,55)) ?></td>
              <td style="font-size:.72rem;color:#8B0000;font-weight:600"><?= htmlspecialchars($type) ?></td>
              <td><?= statusBadge($status) ?></td>
            </tr>
            <?php endforeach; ?>
          </tbody>
        </table></div>
      <?php endif; ?>
    </div>
  </div>
  <div class="card" style="border-top:3px solid #b5460f">
    <div class="card-header" style="background:#fff8f0;border-bottom-color:#ffd6b3">
      <div class="card-header-title" style="color:#b5460f">
        <div class="section-head-icon" style="background:#b5460f">⚡</div>
        Cross-Site Scripting — <?= number_format($s['xss_total']) ?>
      </div>
    </div>
    <div class="card-body" style="padding:14px">
      <?php if ($s['xss_types']): $mx=max($s['xss_types']); ?>
        <div class="sec-label">Типи атак</div>
        <?php foreach ($s['xss_types'] as $t=>$c): ?>
        <div class="prog-wrap">
          <div class="prog-label" style="min-width:200px" title="<?= htmlspecialchars($t) ?>"><?= htmlspecialchars(substr($t,0,32)) ?></div>
          <?= bar($c,$mx,'#b5460f,#e67e22') ?>
        </div>
        <?php endforeach; endif; ?>
      <?php if ($s['xss_by_ip']): $mx=max($s['xss_by_ip']); ?>
        <div class="sec-label">Топ атакуючих IP</div>
        <?php foreach (array_slice($s['xss_by_ip'],0,10,true) as $ip=>$c): ?>
        <div class="prog-wrap">
          <div class="prog-label"><?= htmlspecialchars($ip) ?></div>
          <?= bar($c,$mx,'#b5460f,#e67e22') ?>
        </div>
        <?php endforeach; endif; ?>
      <?php if ($s['xss_hits']): ?>
        <div class="sec-label">Останні запити</div>
        <div class="attack-hits"><table class="data-table">
          <thead><tr><th>IP</th><th>M</th><th>URL</th><th>Тип</th><th>St</th></tr></thead>
          <tbody>
            <?php foreach ($s['xss_hits'] as [$ip,$time,$method,$uri,$status,$type]): ?>
            <tr>
              <td class="mono"><?= htmlspecialchars($ip) ?></td>
              <td><span class="badge badge-info"><?= htmlspecialchars($method) ?></span></td>
              <td class="mono" style="font-size:.72rem;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="<?= htmlspecialchars($uri) ?>"><?= htmlspecialchars(substr($uri,0,55)) ?></td>
              <td style="font-size:.72rem;color:#b5460f;font-weight:600"><?= htmlspecialchars($type) ?></td>
              <td><?= statusBadge($status) ?></td>
            </tr>
            <?php endforeach; ?>
          </tbody>
        </table></div>
      <?php endif; ?>
    </div>
  </div>
</div>

<?php if ($s['attack_top_ips']): $mx=max($s['attack_top_ips']); ?>
<div class="card mb-4" style="border-top:3px solid #8B0000">
  <div class="card-header" style="background:#fdf0f0;border-bottom-color:#f5c6c6">
    <div class="card-header-title" style="color:#8B0000">
      <div class="section-head-icon" style="background:#8B0000">🎯</div>
      Топ атакуючих IP (SQLi + XSS)
    </div>
  </div>
  <div class="card-body" style="padding:14px">
    <?php foreach ($s['attack_top_ips'] as $ip=>$cnt):
      $si=$s['sqli_by_ip'][$ip]??0; $xi=$s['xss_by_ip'][$ip]??0; ?>
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:10px">
      <div style="font-family:var(--font-mono);font-size:.78rem;min-width:130px"><?= htmlspecialchars($ip) ?></div>
      <?= bar($cnt,$mx,'#8B0000,#c0392b') ?>
      <div style="display:flex;gap:6px;white-space:nowrap">
        <?php if ($si): ?><span class="badge" style="background:#fdf0f0;color:#8B0000">💉 <?= $si ?></span><?php endif; ?>
        <?php if ($xi): ?><span class="badge" style="background:#fff8f0;color:#b5460f">⚡ <?= $xi ?></span><?php endif; ?>
      </div>
    </div>
    <?php endforeach; ?>
  </div>
</div>
<?php endif; ?>
<?php endif; /* sqli||xss */ ?>

<?php if (($s['parse_errors'] ?? 0) > 0 || ($s['tls_probes'] ?? 0) > 0 || ($s['binary_lines'] ?? 0) > 0): ?>
<div class="card mb-4" style="border-top:3px solid var(--orange-warn)">
  <div class="card-header" style="background:#fff8f0;border-bottom-color:#ffe0b2">
    <div class="card-header-title" style="color:var(--orange-warn)">
      <div class="section-head-icon" style="background:#e65100">⚠</div>
      Некоректні рядки в лог-файлі
    </div>
  </div>
  <div class="card-body" style="padding:14px">
    <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:12px;margin-bottom:<?= (($s['tls_probes']??0)>0) ? '16' : '0' ?>px">

      <?php if (($s['tls_probes'] ?? 0) > 0): ?>
      <div style="background:#fff3e0;border:1px solid #ffcc80;border-radius:8px;padding:12px 16px">
        <div style="font-size:1.3rem;font-weight:800;color:var(--orange-warn)"><?= number_format($s['tls_probes']) ?></div>
        <div style="font-size:.78rem;font-weight:600;color:var(--orange-warn);margin-top:2px">🔒 TLS Handshake</div>
        <div style="font-size:.72rem;color:#a0522d;margin-top:4px">HTTPS-запити на HTTP порт.<br>Налаштуйте redirect 80→443.</div>
      </div>
      <?php endif; ?>

      <?php if (($s['binary_lines'] ?? 0) > 0): ?>
      <div style="background:#fce4ec;border:1px solid #f48fb1;border-radius:8px;padding:12px 16px">
        <div style="font-size:1.3rem;font-weight:800;color:#c62828"><?= number_format($s['binary_lines']) ?></div>
        <div style="font-size:.78rem;font-weight:600;color:#c62828;margin-top:2px">⬛ Бінарні рядки</div>
        <div style="font-size:.72rem;color:#7b1a1a;margin-top:4px">Нечитабельні байти.<br>Можливо сканери або атаки.</div>
      </div>
      <?php endif; ?>

      <?php if (($s['parse_errors'] ?? 0) > 0): ?>
      <div style="background:#f5f5f5;border:1px solid #e0e0e0;border-radius:8px;padding:12px 16px">
        <div style="font-size:1.3rem;font-weight:800;color:var(--gray-mid)"><?= number_format($s['parse_errors']) ?></div>
        <div style="font-size:.78rem;font-weight:600;color:var(--gray-mid);margin-top:2px">📄 Інший формат</div>
        <div style="font-size:.72rem;color:var(--gray-light);margin-top:4px">Не відповідає Nginx combined.<br>Можливо інший формат логів.</div>
      </div>
      <?php endif; ?>

    </div>
    <?php if (($s['tls_probes'] ?? 0) > 0): ?>
    <div style="background:var(--blue-ultra);border-radius:8px;padding:10px 14px;font-size:.77rem;color:var(--gray-mid)">
      💡 <strong>Рекомендація:</strong> Додайте в Nginx redirect HTTP→HTTPS:
      <code style="display:block;margin-top:6px;padding:6px 10px;background:var(--white);border-radius:4px;font-size:.75rem;color:var(--blue-dark)">server { listen 80; return 301 https://$host$request_uri; }</code>
    </div>
    <?php endif; ?>
  </div>
</div>
<?php endif; ?>


<?php elseif (($s['type'] ?? '') === 'mikrotik'): /* MIKROTIK */
$fwTotal  = $s['fw_total'];
$maxHrMt  = $s['hours'] ? max($s['hours']) ?: 1 : 1;
?>

<!-- ═══ MIKROTIK STAT CARDS ═══ -->
<div class="stats-row">
  <div class="stat-card">
    <div class="stat-label">Рядків лога</div>
    <div class="stat-value"><?= number_format($s['total_lines']) ?></div>
    <div class="stat-sub">
      <?= $s['ts_start'] ? date('d.m.Y',$s['ts_start']) : '' ?>
      <?= ($s['ts_start']&&$s['ts_end']) ? ' – '.date('d.m.Y',$s['ts_end']) : '' ?>
    </div>
  </div>
  <div class="stat-card" style="border-top-color:#8B0000">
    <div class="stat-label">FW Заблоковано</div>
    <div class="stat-value" style="color:#8B0000"><?= number_format($s['fw_dropped'] + $s['fw_rejected']) ?></div>
    <div class="stat-sub">drop: <?= number_format($s['fw_dropped']) ?> · reject: <?= number_format($s['fw_rejected']) ?></div>
  </div>
  <div class="stat-card green">
    <div class="stat-label">FW Дозволено</div>
    <div class="stat-value" style="color:var(--green-ok)"><?= number_format($s['fw_accepted']) ?></div>
    <div class="stat-sub">accept правила</div>
  </div>
  <?php if (($s['fw_logged'] ?? 0) > 0): ?>
  <div class="stat-card" style="border-top-color:var(--blue-main)">
    <div class="stat-label">FW Logged</div>
    <div class="stat-value" style="color:var(--blue-dark)"><?= number_format($s['fw_logged']) ?></div>
    <div class="stat-sub">loggged трафік</div>
  </div>
  <?php endif; ?>
  <div class="stat-card" style="border-top-color:var(--orange-warn)">
    <div class="stat-label">Невдалих логінів</div>
    <div class="stat-value" style="color:var(--orange-warn)"><?= number_format(array_sum($s['login_fail'])) ?></div>
    <div class="stat-sub"><?= count($s['login_fail_ip']) ?> унікальних IP</div>
  </div>
  <div class="stat-card">
    <div class="stat-label">PPP/VPN сесій</div>
    <div class="stat-value"><?= number_format($s['ppp_total']) ?></div>
    <div class="stat-sub"><?= count($s['ppp_sessions']) ?> унікальних</div>
  </div>
  <div class="stat-card yellow">
    <div class="stat-label">DHCP видач</div>
    <div class="stat-value"><?= number_format($s['dhcp_total']) ?></div>
    <div class="stat-sub"><?= count($s['dhcp_leases']) ?> унікальних IP</div>
  </div>
  <?php if (!empty($s['crit_events'])): ?>
  <div class="stat-card" style="border-top-color:#8B0000">
    <div class="stat-label">Критичні події</div>
    <div class="stat-value" style="color:#8B0000"><?= count($s['crit_events']) ?></div>
    <div class="stat-sub">reboot / voltage / power</div>
  </div>
  <?php endif; ?>
  <div class="stat-card">
    <div class="stat-label">Пікова година</div>
    <div class="stat-value" style="color:var(--orange-warn)"><?= sprintf('%02d:00',$s['peak_hour']) ?></div>
    <div class="stat-sub"><?= number_format($s['hours'][$s['peak_hour']]) ?> подій</div>
  </div>
</div>

<!-- ═══ MIKROTIK: Розбивка по датах ═══ -->
<?php if (!empty($s['days'])): ?>
<div class="mb-4"><div class="card">
  <div class="card-header"><div class="card-header-title"><div class="section-head-icon">📅</div> Активність по датах</div></div>
  <div class="card-body" style="padding:0">
    <div style="overflow-x:auto;max-height:340px;overflow-y:auto">
    <table class="date-table">
      <thead><tr><th>Дата</th><th>Подій</th><th>Розподіл</th></tr></thead>
      <tbody>
      <?php $maxDay=max($s['days']);
      foreach ($s['days'] as $dk=>$cnt):
        $w=$maxDay>0?max(4,round($cnt/$maxDay*200)):4;
        $dt=DateTime::createFromFormat('Y-m-d',$dk);
        $lbl=$dt?$dt->format('d.m.Y').' ('.['Нд','Пн','Вт','Ср','Чт','Пт','Сб'][(int)$dt->format('w')].')':$dk; ?>
      <tr>
        <td style="font-family:var(--font-mono)"><?= $lbl ?></td>
        <td class="num"><?= number_format($cnt) ?></td>
        <td><span class="date-bar" style="width:<?= $w ?>px"></span></td>
      </tr>
      <?php endforeach; ?>
      </tbody>
    </table>
    </div>
  </div>
</div></div>
<?php endif; ?>

<!-- ═══ MIKROTIK: Погодинна активність + Topics ═══ -->
<div class="grid-2 mb-4">
  <div class="card">
    <div class="card-header"><div class="card-header-title"><div class="section-head-icon">⏰</div> Активність по годинах</div></div>
    <div class="card-body">
      <div class="hour-chart">
        <?php for ($h=0;$h<24;$h++):
          $cnt=$s['hours'][$h]; $ht=$maxHrMt>0?max(2,(int)round($cnt/$maxHrMt*100)):2; ?>
          <div class="hour-bar" style="height:<?= $ht ?>%">
            <div class="hour-bar-tip"><?= sprintf('%02d:00',$h) ?> — <?= number_format($cnt) ?></div>
          </div>
        <?php endfor; ?>
      </div>
      <div style="display:flex;justify-content:space-between;font-size:.65rem;color:var(--gray-light);margin-top:4px;padding:0 4px">
        <span>00</span><span>06</span><span>12</span><span>18</span><span>23</span>
      </div>
    </div>
  </div>
  <?php if (!empty($s['topics'])): ?>
  <div class="card">
    <div class="card-header"><div class="card-header-title"><div class="section-head-icon">🏷</div> Topics (теми логів)</div></div>
    <div class="card-body">
      <?php $maxTopic=max($s['topics']);
      foreach ($s['topics'] as $tp=>$cnt): ?>
      <div class="prog-wrap">
        <div class="prog-label" style="min-width:100px;font-family:var(--font-mono)"><?= htmlspecialchars($tp) ?></div>
        <?= bar($cnt,$maxTopic) ?>
        <div class="prog-count"><?= number_format($cnt) ?></div>
      </div>
      <?php endforeach; ?>
    </div>
  </div>
  <?php endif; ?>
</div>

<!-- ═══ MIKROTIK: Firewall ═══ -->
<?php if ($fwTotal > 0): ?>
<div class="card mb-4" style="border-top:3px solid #8B0000">
  <div class="card-header" style="background:#fdf0f0;border-bottom-color:#f5c6c6">
    <div class="card-header-title" style="color:#8B0000">
      <div class="section-head-icon" style="background:#8B0000">🔥</div>
      Firewall — <?= number_format($fwTotal) ?> подій
    </div>
  </div>
  <div class="card-body">
    <div class="grid-2" style="gap:20px">

      <!-- Дії -->
      <div>
        <div class="sec-label">Дії firewall</div>
        <?php
        $fwActs = ['dropped'=>['Заблоковано (drop)', '#8B0000,#c0392b'], 'rejected'=>['Відхилено (reject)', '#b5460f,#e67e22'], 'accepted'=>['Дозволено (accept)', 'var(--green-ok),#388e3c'], 'logged'=>['Logged (моніторинг)', 'var(--blue-main),var(--blue-light)']];
        $fwActValues = ['dropped'=>$s['fw_dropped'], 'rejected'=>$s['fw_rejected'], 'accepted'=>$s['fw_accepted'], 'logged'=>$s['fw_logged']??0];
        foreach ($fwActs as $key=>[$lbl,$clr]):
          $cnt = $fwActValues[$key] ?? ($s['fw_'.$key] ?? 0); if (!$cnt) continue; ?>
        <div class="prog-wrap">
          <div class="prog-label" style="min-width:180px"><?= $lbl ?></div>
          <?= bar($cnt, $fwTotal, $clr) ?>
          <div class="prog-count"><?= pct($cnt, $fwTotal) ?></div>
        </div>
        <?php endforeach; ?>

        <?php if (!empty($s['fw_by_chain'])): ?>
        <div class="sec-label" style="margin-top:16px">Ланцюжки (chain)</div>
        <?php $maxCh=max($s['fw_by_chain']);
        foreach ($s['fw_by_chain'] as $ch=>$cnt): ?>
        <div class="prog-wrap">
          <div class="prog-label" style="min-width:80px;font-family:var(--font-mono)"><?= htmlspecialchars($ch) ?></div>
          <?= bar($cnt,$maxCh) ?>
          <div class="prog-count"><?= pct($cnt,$fwTotal) ?></div>
        </div>
        <?php endforeach; endif; ?>

        <?php if (!empty($s['fw_by_proto'])): ?>
        <div class="sec-label" style="margin-top:16px">Протоколи</div>
        <?php $maxPr=max($s['fw_by_proto']);
        foreach ($s['fw_by_proto'] as $pr=>$cnt): ?>
        <div class="prog-wrap">
          <div class="prog-label" style="min-width:80px;font-family:var(--font-mono)"><?= htmlspecialchars($pr) ?></div>
          <?= bar($cnt,$maxPr,'var(--blue-main),var(--blue-light)') ?>
          <div class="prog-count"><?= number_format($cnt) ?></div>
        </div>
        <?php endforeach; endif; ?>
      </div>

      <!-- Топ IP та порти -->
      <div>
        <?php if (!empty($s['fw_top_src'])): ?>
        <div class="sec-label">🌐 Топ джерела (src IP)</div>
        <?php $maxSrc=max($s['fw_top_src']);
        foreach (array_slice($s['fw_top_src'],0,10,true) as $ip=>$cnt): ?>
        <div class="prog-wrap">
          <div class="prog-label" style="font-family:var(--font-mono)"><?= htmlspecialchars($ip) ?></div>
          <?= bar($cnt,$maxSrc,'#8B0000,#c0392b') ?>
          <div class="prog-count"><?= number_format($cnt) ?></div>
        </div>
        <?php endforeach; endif; ?>

        <?php if (!empty($s['fw_top_ports'])): ?>
        <div class="sec-label" style="margin-top:16px">🎯 Топ цільових портів</div>
        <?php $maxPort=max($s['fw_top_ports']);
        foreach (array_slice($s['fw_top_ports'],0,10,true) as $port=>$cnt): ?>
        <div class="prog-wrap">
          <div class="prog-label" style="font-family:var(--font-mono);font-weight:700"><?= htmlspecialchars($port) ?></div>
          <?= bar($cnt,$maxPort,'var(--orange-warn),#ef6c00') ?>
          <div class="prog-count"><?= number_format($cnt) ?></div>
        </div>
        <?php endforeach; endif; ?>
      </div>
    </div>

    <!-- Останні FW події -->
    <?php if (!empty($s['fw_hits'])): ?>
    <div class="sec-label" style="margin-top:16px">Останні firewall події</div>
    <div style="overflow-x:auto;max-height:280px;overflow-y:auto">
    <table class="data-table">
      <thead><tr><th>Час</th><th>Дія</th><th>Chain</th><th>Src IP</th><th>Dst IP</th><th>Proto</th><th>Port</th></tr></thead>
      <tbody>
      <?php foreach (array_reverse($s['fw_hits']) as $hit):
        $ac = $hit['action'];
        $acColor = $ac==='dropped'?'#8B0000':($ac==='rejected'?'#b5460f':'var(--green-ok)'); ?>
      <tr>
        <td style="font-size:.72rem;white-space:nowrap"><?= $hit['ts'] ? date('d.m H:i:s',$hit['ts']) : '—' ?></td>
        <td><span style="background:<?= $acColor ?>;color:#fff;padding:1px 7px;border-radius:8px;font-size:.7rem"><?= htmlspecialchars($ac) ?></span></td>
        <td style="font-family:var(--font-mono);font-size:.75rem"><?= htmlspecialchars($hit['chain']) ?></td>
        <td style="font-family:var(--font-mono)"><?= htmlspecialchars($hit['src']) ?></td>
        <td style="font-family:var(--font-mono)"><?= htmlspecialchars($hit['dst']) ?></td>
        <td><?= htmlspecialchars($hit['proto']) ?></td>
        <td><?= $hit['dport'] ? htmlspecialchars($hit['dport']) : '—' ?></td>
      </tr>
      <?php endforeach; ?>
      </tbody>
    </table>
    </div>
    <?php endif; ?>
  </div>
</div>
<?php endif; ?>

<!-- ═══ MIKROTIK: Auth ═══ -->
<?php if (!empty($s['login_fail']) || !empty($s['login_ok'])): ?>
<div class="grid-2 mb-4">
  <?php if (!empty($s['login_fail'])): ?>
  <div class="card" style="border-top:3px solid var(--orange-warn)">
    <div class="card-header" style="background:#fff8f0;border-bottom-color:#ffe0b2">
      <div class="card-header-title" style="color:var(--orange-warn)">
        <div class="section-head-icon" style="background:#e65100">⚠</div>
        Невдалі логіни — <?= number_format(array_sum($s['login_fail'])) ?>
      </div>
    </div>
    <div class="card-body">
      <?php if ($s['login_fail_ip']): ?>
      <div class="sec-label">Атакуючі IP</div>
      <?php $maxFip=max($s['login_fail_ip']);
      foreach (array_slice($s['login_fail_ip'],0,10,true) as $ip=>$cnt): ?>
      <div class="prog-wrap">
        <div class="prog-label" style="font-family:var(--font-mono)"><?= htmlspecialchars($ip) ?></div>
        <?= bar($cnt,$maxFip,'var(--orange-warn),#ef6c00') ?>
        <div class="prog-count"><?= number_format($cnt) ?></div>
      </div>
      <?php endforeach; endif; ?>
      <?php $maxFail=max($s['login_fail']);
      if (count($s['login_fail_ip']) < count($s['login_fail'])): ?>
      <div class="sec-label" style="margin-top:12px">User@IP</div>
      <?php foreach (array_slice($s['login_fail'],0,8,true) as $key=>$cnt): ?>
      <div class="prog-wrap">
        <div class="prog-label" style="font-family:var(--font-mono);font-size:.75rem"><?= htmlspecialchars($key) ?></div>
        <?= bar($cnt,$maxFail,'#c62828,#e53935') ?>
        <div class="prog-count"><?= number_format($cnt) ?></div>
      </div>
      <?php endforeach; endif; ?>
    </div>
  </div>
  <?php endif; ?>

  <?php if (!empty($s['login_ok']) || !empty($s['login_svc'])): ?>
  <div class="card" style="border-top:3px solid var(--green-ok)">
    <div class="card-header" style="background:var(--green-light);border-bottom-color:#c8e6c9">
      <div class="card-header-title" style="color:#1b5e20">
        <div class="section-head-icon" style="background:var(--green-ok)">✓</div>
        Успішні логіни — <?= number_format(array_sum($s['login_ok'])) ?>
      </div>
    </div>
    <div class="card-body">
      <?php if ($s['login_ok']): $maxOk=max($s['login_ok']);
      foreach ($s['login_ok'] as $u=>$cnt): ?>
      <div class="prog-wrap">
        <div class="prog-label" style="font-family:var(--font-mono)"><?= htmlspecialchars($u) ?></div>
        <?= bar($cnt,$maxOk,'var(--green-ok),#388e3c') ?>
        <div class="prog-count"><?= number_format($cnt) ?></div>
      </div>
      <?php endforeach; endif; ?>
      <?php if ($s['login_svc']): ?>
      <div class="sec-label" style="margin-top:12px">Сервіси</div>
      <?php $maxSvc=max($s['login_svc']);
      foreach ($s['login_svc'] as $sv=>$cnt): ?>
      <div class="prog-wrap">
        <div class="prog-label" style="font-family:var(--font-mono)"><?= htmlspecialchars($sv) ?></div>
        <?= bar($cnt,$maxSvc) ?>
        <div class="prog-count"><?= number_format($cnt) ?></div>
      </div>
      <?php endforeach; endif; ?>
    </div>
  </div>
  <?php endif; ?>
</div>
<?php endif; ?>

<!-- ═══ MIKROTIK: PPP/VPN + DHCP ═══ -->
<?php if (!empty($s['ppp_sessions']) || !empty($s['dhcp_leases'])): ?>
<div class="grid-2 mb-4">
  <?php if (!empty($s['ppp_sessions'])): ?>
  <div class="card">
    <div class="card-header"><div class="card-header-title"><div class="section-head-icon">🔒</div> PPP/VPN сесії (<?= number_format($s['ppp_total']) ?>)</div></div>
    <div class="card-body">
      <?php $maxPpp=max($s['ppp_sessions']);
      foreach ($s['ppp_sessions'] as $u=>$cnt): ?>
      <div class="prog-wrap">
        <div class="prog-label" style="font-family:var(--font-mono);font-size:.78rem"><?= htmlspecialchars($u) ?></div>
        <?= bar($cnt,$maxPpp,'var(--blue-main),var(--blue-light)') ?>
        <div class="prog-count"><?= number_format($cnt) ?></div>
      </div>
      <?php endforeach; ?>
    </div>
  </div>
  <?php endif; ?>

  <?php if (!empty($s['dhcp_leases'])): ?>
  <div class="card">
    <div class="card-header"><div class="card-header-title"><div class="section-head-icon">📡</div> DHCP видачі (<?= number_format($s['dhcp_total']) ?>)</div></div>
    <div class="card-body" style="padding:0">
      <div style="overflow-x:auto;max-height:280px;overflow-y:auto">
      <table class="data-table">
        <thead><tr><th>IP адреса</th><th>MAC адреса</th></tr></thead>
        <tbody>
        <?php foreach ($s['dhcp_leases'] as $ip=>$mac): ?>
        <tr>
          <td style="font-family:var(--font-mono)"><?= htmlspecialchars($ip) ?></td>
          <td style="font-family:var(--font-mono);font-size:.75rem"><?= htmlspecialchars($mac) ?></td>
        </tr>
        <?php endforeach; ?>
        </tbody>
      </table>
      </div>
    </div>
  </div>
  <?php endif; ?>
</div>
<?php endif; ?>

<!-- ═══ MIKROTIK: Interface + Critical events ═══ -->
<?php if (!empty($s['if_events']) || !empty($s['crit_events'])): ?>
<div class="grid-2 mb-4">
  <?php if (!empty($s['if_events'])): ?>
  <div class="card">
    <div class="card-header"><div class="card-header-title"><div class="section-head-icon">🔌</div> Інтерфейси (link up/down)</div></div>
    <div class="card-body" style="padding:0">
      <table class="data-table">
        <thead><tr><th>Інтерфейс</th><th>Link Up</th><th>Link Down</th></tr></thead>
        <tbody>
        <?php foreach ($s['if_events'] as $iface=>$ev): ?>
        <tr>
          <td style="font-family:var(--font-mono);font-weight:600"><?= htmlspecialchars($iface) ?></td>
          <td style="color:var(--green-ok);font-weight:700"><?= $ev['up'] ?></td>
          <td style="color:var(--red-err);font-weight:700"><?= $ev['down'] ?></td>
        </tr>
        <?php endforeach; ?>
        </tbody>
      </table>
    </div>
  </div>
  <?php endif; ?>

  <?php if (!empty($s['crit_events'])): ?>
  <div class="card" style="border-top:3px solid #8B0000">
    <div class="card-header" style="background:#fdf0f0;border-bottom-color:#f5c6c6">
      <div class="card-header-title" style="color:#8B0000">
        <div class="section-head-icon" style="background:#8B0000">🚨</div>
        Критичні події
      </div>
    </div>
    <div class="card-body" style="padding:0">
      <table class="data-table">
        <thead><tr><th>Час</th><th>Подія</th></tr></thead>
        <tbody>
        <?php foreach (array_reverse($s['crit_events']) as $ev): ?>
        <tr>
          <td style="white-space:nowrap;font-size:.72rem"><?= $ev['ts'] ? date('d.m.Y H:i:s',$ev['ts']) : '—' ?></td>
          <td style="font-size:.78rem"><?= htmlspecialchars($ev['msg']) ?></td>
        </tr>
        <?php endforeach; ?>
        </tbody>
      </table>
    </div>
  </div>
  <?php endif; ?>
</div>
<?php endif; ?>

<?php if ($s['parse_errors'] > 0): ?>
<div class="alert alert-warning">
  <span class="alert-icon">⚠</span>
  <strong><?= number_format($s['parse_errors']) ?> рядків</strong> пропущено — не відповідають жодному формату Mikrotik log.
</div>
<?php endif; ?>

<?php else: /* BIND */
$s += [
    'total'          => 0,
    'total_lines'    => 0,
    'parse_errors'   => 0,
    'hours'          => array_fill(0, 24, 0),
    'days'           => [],
    'query_types'    => [],
    'query_class'    => [],
    'top_domains'    => [],
    'top_clients'    => [],
    'top_tlds'       => [],
    'flags'          => [],
    'ptr_queries'    => 0,
    'any_queries'    => [],
    'any_total'      => 0,
    'nxdomains'      => [],
    'refused'        => [],
    'scanners'       => [],
    'unique_clients' => 0,
    'unique_domains' => 0,
];
$bTotal   = $s['total'];
$bMaxHr   = $s['hours'] ? max($s['hours']) ?: 1 : 1;
$bMaxCl   = $s['top_clients']  ? max($s['top_clients'])  : 1;
$bMaxDom  = $s['top_domains']  ? max($s['top_domains'])  : 1;
$bMaxType = $s['query_types']  ? max($s['query_types'])  : 1;
?>

<!-- ═══ BIND STAT CARDS ═══ -->
<div class="stats-row">
  <div class="stat-card">
    <div class="stat-label">Всього запитів</div>
    <div class="stat-value"><?= number_format($bTotal) ?></div>
    <div class="stat-sub">DNS queries</div>
  </div>
  <div class="stat-card" style="border-top-color:var(--green-ok)">
    <div class="stat-label">Унікальних клієнтів</div>
    <div class="stat-value" style="color:var(--green-ok)"><?= number_format($s['unique_clients']) ?></div>
    <div class="stat-sub">IP адрес</div>
  </div>
  <div class="stat-card" style="border-top-color:var(--blue-light)">
    <div class="stat-label">Унікальних доменів</div>
    <div class="stat-value" style="color:var(--blue-dark)"><?= number_format($s['unique_domains']) ?></div>
    <div class="stat-sub">queried names</div>
  </div>
  <div class="stat-card" style="border-top-color:var(--orange-warn)">
    <div class="stat-label">PTR запити</div>
    <div class="stat-value" style="color:var(--orange-warn)"><?= number_format($s['ptr_queries']) ?></div>
    <div class="stat-sub">reverse DNS</div>
  </div>
  <div class="stat-card" style="border-top-color:#8B0000">
    <div class="stat-label">ANY запити</div>
    <div class="stat-value" style="color:#8B0000"><?= number_format($s['any_total']) ?></div>
    <div class="stat-sub">DDoS amplification</div>
  </div>
  <div class="stat-card" style="border-top-color:var(--gray-mid)">
    <div class="stat-label">Сканерів виявлено</div>
    <div class="stat-value" style="color:var(--gray-mid)"><?= count($s['scanners']) ?></div>
    <div class="stat-sub">>50 різних доменів</div>
  </div>
</div>

<!-- ═══ BIND: Розбивка по датах ═══ -->
<?php if (!empty($s['days'])): ?>
<div class="mb-4"><div class="card">
  <div class="card-header"><div class="card-header-title"><div class="section-head-icon">📅</div> Активність по датах</div></div>
  <div class="card-body" style="padding:0">
    <div style="overflow-x:auto;max-height:340px;overflow-y:auto">
    <table class="date-table">
      <thead><tr><th>Дата</th><th>Запитів</th><th>Розподіл</th></tr></thead>
      <tbody>
      <?php
        $maxDay = max($s['days']);
        foreach ($s['days'] as $dk => $cnt):
          $w  = $maxDay>0 ? max(4,round($cnt/$maxDay*200)) : 4;
          $dt = DateTime::createFromFormat('Y-m-d', $dk);
          $lbl= $dt ? $dt->format('d.m.Y').' ('.['Нд','Пн','Вт','Ср','Чт','Пт','Сб'][(int)$dt->format('w')].')' : $dk;
      ?>
      <tr>
        <td style="font-family:var(--font-mono)"><?= $lbl ?></td>
        <td class="num"><?= number_format($cnt) ?></td>
        <td><span class="date-bar" style="width:<?= $w ?>px"></span></td>
      </tr>
      <?php endforeach; ?>
      </tbody>
    </table>
    </div>
  </div>
</div></div>
<?php endif; ?>

<!-- ═══ BIND: Погодинна активність ═══ -->
<div class="mb-4"><div class="card">
  <div class="card-header"><div class="card-header-title"><div class="section-head-icon">⏰</div> Активність по годинах</div></div>
  <div class="card-body">
    <div class="hour-chart">
      <?php for ($h=0;$h<24;$h++):
        $cnt=$s['hours'][$h]; $ht=$bMaxHr>0?max(2,(int)round($cnt/$bMaxHr*100)):2; ?>
        <div class="hour-bar" style="height:<?= $ht ?>%">
          <div class="hour-bar-tip"><?= sprintf('%02d:00',$h) ?> — <?= number_format($cnt) ?></div>
        </div>
      <?php endfor; ?>
    </div>
    <div style="display:flex;justify-content:space-between;font-size:.65rem;color:var(--gray-light);margin-top:4px;padding:0 4px">
      <span>00</span><span>06</span><span>12</span><span>18</span><span>23</span>
    </div>
  </div>
</div></div>

<!-- ═══ BIND: Типи запитів + Топ клієнти ═══ -->
<div class="grid-2 mb-4">
  <div class="card">
    <div class="card-header"><div class="card-header-title"><div class="section-head-icon">🔤</div> Типи запитів</div></div>
    <div class="card-body">
      <?php foreach ($s['query_types'] as $qt => $cnt): ?>
      <div class="prog-wrap">
        <div class="prog-label" style="min-width:60px;font-family:var(--font-mono);font-weight:700"><?= htmlspecialchars($qt) ?></div>
        <?= bar($cnt, $bMaxType) ?>
        <div class="prog-count"><?= pct($cnt,$bTotal) ?></div>
      </div>
      <?php endforeach; ?>
    </div>
  </div>
  <div class="card">
    <div class="card-header"><div class="card-header-title"><div class="section-head-icon">💻</div> Топ клієнти</div></div>
    <div class="card-body">
      <?php foreach (array_slice($s['top_clients'],0,15,true) as $ip => $cnt): ?>
      <div class="prog-wrap">
        <div class="prog-label" style="font-family:var(--font-mono)"><?= htmlspecialchars($ip) ?></div>
        <?= bar($cnt, $bMaxCl) ?>
        <div class="prog-count"><?= number_format($cnt) ?></div>
      </div>
      <?php endforeach; ?>
    </div>
  </div>
</div>

<!-- ═══ BIND: Топ домени + TLD ═══ -->
<div class="grid-2 mb-4">
  <div class="card">
    <div class="card-header"><div class="card-header-title"><div class="section-head-icon">🌐</div> Топ запитуваних доменів</div></div>
    <div class="card-body">
      <?php foreach (array_slice($s['top_domains'],0,15,true) as $dom => $cnt): ?>
      <div class="prog-wrap">
        <div class="prog-label" style="font-family:var(--font-mono);font-size:.78rem" title="<?= htmlspecialchars($dom) ?>"><?= htmlspecialchars(strlen($dom)>40?substr($dom,0,38).'…':$dom) ?></div>
        <?= bar($cnt, $bMaxDom) ?>
        <div class="prog-count"><?= number_format($cnt) ?></div>
      </div>
      <?php endforeach; ?>
    </div>
  </div>
  <div class="card">
    <div class="card-header"><div class="card-header-title"><div class="section-head-icon">🏷</div> Топ TLD</div></div>
    <div class="card-body">
      <?php $bMaxTld = $s['top_tlds'] ? max($s['top_tlds']) : 1;
      foreach (array_slice($s['top_tlds'],0,15,true) as $tld => $cnt): ?>
      <div class="prog-wrap">
        <div class="prog-label" style="font-family:var(--font-mono);font-weight:700">.<?= htmlspecialchars($tld) ?></div>
        <?= bar($cnt, $bMaxTld) ?>
        <div class="prog-count"><?= pct($cnt,$bTotal) ?></div>
      </div>
      <?php endforeach; ?>
    </div>
  </div>
</div>

<!-- ═══ BIND: Аномалії ═══ -->
<?php if ($s['any_total']>0 || $s['nxdomains'] || $s['refused'] || $s['scanners']): ?>
<div class="mb-4"><div class="card" style="border-top:3px solid #8B0000">
  <div class="card-header" style="background:#fdf0f0;border-bottom-color:#f5c6c6">
    <div class="card-header-title" style="color:#8B0000">
      <div class="section-head-icon" style="background:#8B0000">⚠</div>
      Аномалії та підозрілі запити
    </div>
  </div>
  <div class="card-body">
    <div class="grid-2" style="gap:20px">

      <?php if ($s['any_total']>0): ?>
      <div>
        <div class="sec-label">💥 ANY запити (DDoS amplification) — <?= number_format($s['any_total']) ?> всього</div>
        <?php $mAny=max($s['any_queries'])?:1;
        foreach ($s['any_queries'] as $ip=>$cnt): ?>
        <div class="prog-wrap">
          <div class="prog-label" style="font-family:var(--font-mono)"><?= htmlspecialchars($ip) ?></div>
          <?= bar($cnt,$mAny,'#8B0000,#c0392b') ?>
          <div class="prog-count"><?= number_format($cnt) ?></div>
        </div>
        <?php endforeach; ?>
      </div>
      <?php endif; ?>

      <?php if ($s['nxdomains']): ?>
      <div>
        <div class="sec-label">❌ Топ NXDOMAIN (не існуючі домени)</div>
        <?php $mNx=max($s['nxdomains'])?:1;
        foreach ($s['nxdomains'] as $dom=>$cnt): ?>
        <div class="prog-wrap">
          <div class="prog-label" style="font-family:var(--font-mono);font-size:.76rem" title="<?= htmlspecialchars($dom) ?>"><?= htmlspecialchars(strlen($dom)>35?substr($dom,0,33).'…':$dom) ?></div>
          <?= bar($cnt,$mNx,'var(--orange-warn),#ef6c00') ?>
          <div class="prog-count"><?= number_format($cnt) ?></div>
        </div>
        <?php endforeach; ?>
      </div>
      <?php endif; ?>

      <?php if ($s['refused']): ?>
      <div>
        <div class="sec-label">🚫 REFUSED клієнти</div>
        <?php $mRef=max($s['refused'])?:1;
        foreach ($s['refused'] as $ip=>$cnt): ?>
        <div class="prog-wrap">
          <div class="prog-label" style="font-family:var(--font-mono)"><?= htmlspecialchars($ip) ?></div>
          <?= bar($cnt,$mRef,'#c62828,#e53935') ?>
          <div class="prog-count"><?= number_format($cnt) ?></div>
        </div>
        <?php endforeach; ?>
      </div>
      <?php endif; ?>

      <?php if ($s['scanners']): ?>
      <div>
        <div class="sec-label">🔍 Можливі DNS-сканери (>50 різних доменів)</div>
        <?php $mSc=max($s['scanners'])?:1;
        foreach ($s['scanners'] as $ip=>$cnt): ?>
        <div class="prog-wrap">
          <div class="prog-label" style="font-family:var(--font-mono)"><?= htmlspecialchars($ip) ?></div>
          <?= bar($cnt,$mSc,'var(--orange-warn),#ef6c00') ?>
          <div class="prog-count"><?= $cnt ?> доменів</div>
        </div>
        <?php endforeach; ?>
      </div>
      <?php endif; ?>

    </div>
  </div>
</div></div>
<?php endif; ?>

<?php if ($s['parse_errors']>0): ?>
<div class="alert alert-warning">
  <span class="alert-icon">⚠</span>
  <strong><?= number_format($s['parse_errors']) ?> рядків</strong> пропущено — не відповідають формату BIND query log.
</div>
<?php endif; ?>

<?php endif; /* BIND */ ?>

<?php endif; /* stats > 0 */ ?>

</div></main>

<?php renderFooter(); ?>
</div>
<script>
async function saveReport() {
  const btn = document.querySelector('[onclick="saveReport()"]');
  const origText = btn.innerHTML;
  btn.innerHTML = '⏳ Формуємо…';
  btn.disabled = true;

  try {
    // Завантажуємо CSS
    const cssLinks = [...document.querySelectorAll('link[rel="stylesheet"]')];
    let inlineCSS = '';
    for (const link of cssLinks) {
      try {
        const r = await fetch(link.href);
        inlineCSS += await r.text() + '\n';
      } catch(e) {}
    }

    // Клонуємо документ
    const clone = document.documentElement.cloneNode(true);

    // Видаляємо навігацію, хедер, кнопки дій — лишаємо тільки контент
    const removeSelectors = [
      '.govua-strip', '.site-header', '.site-nav',
      '.breadcrumbs', '.site-footer',
      '[onclick="saveReport()"]',
      'a.btn[href*="logs.php"]',
      'a.btn[href*="REQUEST_URI"]',
    ];
    removeSelectors.forEach(sel => {
      clone.querySelectorAll(sel).forEach(el => el.remove());
    });

    // Видаляємо зовнішні link CSS
    clone.querySelectorAll('link[rel="stylesheet"]').forEach(el => el.remove());

    // Вставляємо інлайн CSS
    const styleEl = clone.querySelector('style') || clone.querySelector('head');
    const newStyle = document.createElement('style');
    newStyle.textContent = inlineCSS;
    clone.querySelector('head').insertBefore(newStyle, clone.querySelector('head').firstChild);

    // Додаємо мета-інформацію про звіт
    const now = new Date().toLocaleString('uk-UA');
    const server = <?= json_encode($srv['name'] ?? '') ?>;
    const logFiles = <?= json_encode(implode(', ', $parsedFiles ?: array_map('basename', $files))) ?>;
    const infoBar = document.createElement('div');
    infoBar.style.cssText = 'background:#e8f4fd;border-bottom:2px solid #1565c0;padding:10px 24px;font-size:.8rem;color:#1a237e;display:flex;gap:24px;flex-wrap:wrap';
    infoBar.innerHTML = `
      <span>🖥 <strong>Сервер:</strong> ${server}</span>
      <span>📄 <strong>Файли:</strong> ${logFiles}</span>
      <span>🕐 <strong>Згенеровано:</strong> ${now}</span>
      <span>🔒 <strong>LogPortal</strong> — автономний звіт</span>
    `;
    const pageWrap = clone.querySelector('.page-wrap') || clone.querySelector('body');
    pageWrap.insertBefore(infoBar, pageWrap.firstChild);

    // Фіксуємо відносні URL зображень/шрифтів
    clone.querySelectorAll('img[src]').forEach(img => {
      if (!img.src.startsWith('http')) img.src = new URL(img.getAttribute('src'), location.href).href;
    });

    // Генеруємо ім'я файлу
    const dateStr = new Date().toISOString().slice(0,10);
    const logType = <?= json_encode($logType) ?>;
    const fname = `report_${logType}_${server.replace(/[^a-zA-Z0-9]/g,'_')}_${dateStr}.html`;

    // Завантажуємо
    const html = '<!DOCTYPE html>\n' + clone.outerHTML;
    const blob = new Blob([html], {type: 'text/html;charset=utf-8'});
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = fname;
    a.click();
    URL.revokeObjectURL(a.href);

    btn.innerHTML = '✓ Збережено';
    setTimeout(() => { btn.innerHTML = origText; btn.disabled = false; }, 2000);
  } catch(e) {
    btn.innerHTML = '✗ Помилка';
    btn.disabled = false;
    console.error(e);
    setTimeout(() => { btn.innerHTML = origText; }, 2000);
  }
}
</script>
</body>
</html>
