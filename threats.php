<?php
/* LogPortal — threats.php — Дашборд загроз */
require_once 'includes/auth.php';
require_once 'includes/db.php';
require_once 'includes/ssh.php';
require_once 'includes/layout.php';
require_once 'includes/nginx_parser.php';
require_once 'includes/postfix_parser.php';

requireAuth();
sendSecurityHeaders();
$user = currentUser();
$sid  = (int)($_GET['sid'] ?? 0);
$srv  = null;
if ($sid) {
    $db2 = getDB();
    $st  = $db2->prepare("SELECT * FROM servers WHERE id=?");
    $st->execute([$sid]);
    $row = $st->fetch();
    if ($row && ($row['user_id'] == $user['id'] || $user['role'] === 'admin')) $srv = $row;
}

/* ── Налаштування Email ── */
$db = getDB();
function _tSetting(PDO $db, string $key): string {
    $r = $db->query("SELECT value FROM settings WHERE key='$key'");
    return $r ? ($r->fetchColumn() ?: '') : '';
}
$smtpHost    = _tSetting($db, 'smtp_host');
$smtpPort    = _tSetting($db, 'smtp_port') ?: '25';
$smtpUser    = _tSetting($db, 'smtp_user');
$smtpPassEnc = _tSetting($db, 'smtp_pass');
$smtpPass    = $smtpPassEnc ? decrypt($smtpPassEnc) : '';
$smtpFrom    = _tSetting($db, 'smtp_from');
$alertTo     = _tSetting($db, 'alert_to');

/* ── GeoIP через ip-api.com (batch, до 100 IP, без ключа) ── */
function geoipBatch(array $ips): array {
    if (empty($ips)) return [];
    $batch   = array_slice(array_unique($ips), 0, 100);
    $payload = json_encode(array_map(fn($ip) => ['query'=>$ip,'fields'=>'query,country,countryCode,city'], $batch));
    $ctx     = stream_context_create(['http'=>['method'=>'POST','header'=>"Content-Type: application/json\r\n",
               'content'=>$payload,'timeout'=>5,'ignore_errors'=>true]]);
    $raw     = @file_get_contents('http://ip-api.com/batch', false, $ctx);
    if (!$raw) return [];
    $data    = json_decode($raw, true) ?? [];
    $result  = [];
    foreach ($data as $row) { $result[$row['query']] = $row; }
    return $result;
}

/* ── Відправка Email алерту через SMTP (socket) ── */
function sendEmailAlert(string $host, string $port, string $user, string $pass,
                        string $from, string $to, string $subject,
                        string $body, string $htmlAttachment = ''): bool {
    if (!$host || !$to || !$from) return false;
    $port   = (int)$port ?: 25;
    $prefix = ($port === 465) ? 'ssl://' : '';
    $sock   = @fsockopen($prefix . $host, $port, $errno, $errstr, 15);
    if (!$sock) return false;
    stream_set_timeout($sock, 15);
    $readAll = function() use (&$sock): string {
        $last = '';
        while (($line = fgets($sock, 1024)) !== false) {
            $last = $line;
            if (strlen($line) >= 4 && $line[3] === ' ') break;
        }
        return $last;
    };
    $send = function(string $cmd) use (&$sock): void { fputs($sock, $cmd . "\r\n"); };
    $code = fn(string $r): int => (int)substr(trim($r), 0, 3);
    $r    = $readAll();
    if ($code($r) !== 220) { fclose($sock); return false; }
    $send("EHLO logportal"); $r = $readAll();
    if ($code($r) < 200 || $code($r) >= 300) { fclose($sock); return false; }
    if ($port === 587) {
        $send("STARTTLS"); $r = $readAll();
        if ($code($r) !== 220) { fclose($sock); return false; }
        stream_socket_enable_crypto($sock, true, STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT | STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT);
        $send("EHLO logportal");
        do { $r = fgets($sock, 1024); } while ($r !== false && strlen($r) >= 4 && $r[3] === '-');
    }
    if ($user !== '' && $pass !== '') {
        $send("AUTH LOGIN"); $r = $readAll();
        if ($code($r) !== 334) { fclose($sock); return false; }
        $send(base64_encode($user)); $r = $readAll();
        if ($code($r) !== 334) { fclose($sock); return false; }
        $send(base64_encode($pass)); $r = $readAll();
        if ($code($r) !== 235) { fclose($sock); return false; }
    }
    $send("MAIL FROM:<{$from}>"); $r = $readAll();
    if ($code($r) < 200 || $code($r) >= 300) { fclose($sock); return false; }
    $send("RCPT TO:<{$to}>"); $r = $readAll();
    if ($code($r) < 200 || $code($r) >= 300) { fclose($sock); return false; }
    $send("DATA"); $r = $readAll();
    if ($code($r) !== 354) { fclose($sock); return false; }
    $boundary = 'LP_' . md5(uniqid());
    $msg  = "From: LogPortal <{$from}>\r\nTo: {$to}\r\n";
    $msg .= "Subject: =?UTF-8?B?" . base64_encode($subject) . "?=\r\nMIME-Version: 1.0\r\n";
    if ($htmlAttachment !== '') {
        $fname = 'threats_report_' . date('Y-m-d_Hi') . '.html';
        $msg .= "Content-Type: multipart/mixed; boundary=\"$boundary\"\r\n\r\n";
        $msg .= "--$boundary\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: base64\r\n\r\n";
        $msg .= chunk_split(base64_encode($body)) . "\r\n";
        $msg .= "--$boundary\r\nContent-Type: text/html; charset=UTF-8; name=\"$fname\"\r\n";
        $msg .= "Content-Transfer-Encoding: base64\r\nContent-Disposition: attachment; filename=\"$fname\"\r\n\r\n";
        $msg .= chunk_split(base64_encode($htmlAttachment)) . "\r\n--$boundary--";
    } else {
        $msg .= "Content-Type: text/plain; charset=UTF-8\r\n\r\n" . $body;
    }
    $msg .= "\r\n.";
    $send($msg); $r = $readAll();
    $send("QUIT"); fclose($sock);
    return $code($r) === 250;
}

/* ── SSH-аналіз (тільки SSH — виконується одразу при виборі сервера) ── */
$sshStats  = null;
$geoData   = [];
$alertSent = false;
$alertError = '';

if ($srv) {
    $conn = sshConnect($srv);
    if ($conn['success']) {
        $sshStats = ['fail_ips'=>[],'success_ips'=>[],'success_after_fail'=>[],'total_fail'=>0,'total_success'=>0];
        $sshBase  = '';
        foreach (['/var/log/auth.log','/var/log/secure'] as $f) {
            $sz = (int)trim(sshExec($conn,"stat -c '%s' ".escapeshellarg($f)." 2>/dev/null"));
            if ($sz > 0) { $sshBase = $f; break; }
        }
        if ($sshBase) {
            $sshSample  = trim(sshExec($conn,'head -3 '.escapeshellarg($sshBase).' 2>/dev/null | tail -1'));
            $b   = escapeshellarg($sshBase);
            $b1  = escapeshellarg($sshBase.'.1');
            $dir = escapeshellarg(dirname($sshBase));
            $pat = escapeshellarg(basename($sshBase).'.*.gz');
            $isIsoFormat = str_starts_with($sshSample,'20') && strlen($sshSample)>10 && $sshSample[4]==='-';
            if ($isIsoFormat) {
                $p = [];
                for ($di=0;$di<7;$di++) $p[]=date('Y-m-d',strtotime("-{$di} days"));
                $sshGrep='grep -F '.implode(' ',array_map(fn($x)=>'-e '.escapeshellarg($x),$p));
            } else {
                $pg=[];
                for ($di=0;$di<7;$di++){$ts=strtotime("-{$di} days");$day=(int)date('j',$ts);$mon=date('M',$ts);$pg[]=$mon.'  '.$day;if($day>=10)$pg[]=$mon.' '.$day;}
                $sshGrep='grep -F '.implode(' ',array_map(fn($x)=>'-e '.escapeshellarg($x),$pg));
            }
            $sshCatCmd='{ cat '.$b.' 2>/dev/null; cat '.$b1.' 2>/dev/null; find '.$dir.' -maxdepth 1 -name '.$pat.' 2>/dev/null | sort -rV | while read f; do zcat "$f" 2>/dev/null; done; }';
            $raw = sshExec($conn,$sshCatCmd.' | '.$sshGrep);
            if (substr_count($raw,"\n")<5) $raw=sshExec($conn,$sshCatCmd);
            if ($raw) {
                $failIps=$successIps=[];
                foreach (explode("\n",$raw) as $line){
                    if (str_contains($line,'Failed password')||str_contains($line,'Invalid user')){
                        if (preg_match('/from\s+(\d+\.\d+\.\d+\.\d+)/',$line,$m)){$failIps[$m[1]]=($failIps[$m[1]]??0)+1;$sshStats['total_fail']++;}
                    } elseif (str_contains($line,'Accepted password')||str_contains($line,'Accepted publickey')||str_contains($line,'Accepted keyboard-interactive')){
                        if (preg_match('/from\s+(\d+\.\d+\.\d+\.\d+)/',$line,$m)){$successIps[$m[1]]=($successIps[$m[1]]??0)+1;$sshStats['total_success']++;}
                    }
                }
                arsort($failIps); arsort($successIps);
                $sshStats['fail_ips']    = array_slice($failIps,   0,20,true);
                $sshStats['success_ips'] = array_slice($successIps,0,10,true);
                foreach (array_keys($successIps) as $ip)
                    if (isset($failIps[$ip]) && $failIps[$ip]>=3)
                        $sshStats['success_after_fail'][$ip]=['fail'=>$failIps[$ip],'success'=>$successIps[$ip]];
            }
        }
        // GeoIP для SSH
        $topGeoIps = array_slice(array_unique(array_merge(array_keys($sshStats['fail_ips']),array_keys($sshStats['success_ips']))),0,50);
        $geoData   = geoipBatch($topGeoIps);
    }
}

/* ── Список серверів ── */
$stList = getDB()->prepare("SELECT * FROM servers WHERE user_id=? ORDER BY name ASC");
$stList->execute([$user['id']]);
$servers = $stList->fetchAll();

/* ── Email-only режим ── */
if (isset($_GET['email_only']) && ($_POST['send_alert'] ?? false)) {
    header('Content-Type: application/json');
    if (!$smtpHost || !$alertTo) { echo json_encode(['ok'=>false,'error'=>'SMTP не налаштовано']); exit; }
    if (!$srv) { echo json_encode(['ok'=>false,'error'=>'Сервер не знайдено']); exit; }

    $analysis = json_decode($_POST['analysis_json'] ?? '{}', true) ?: [];
    $ns = $analysis['nginxStats'] ?? null;
    $ms = $analysis['smtpStats']  ?? null;

    // ── Текстова частина ──
    $lines = ["LogPortal — Звіт загроз", "Сервер: {$srv['name']}", date('d.m.Y H:i:s'), str_repeat('-',40), ""];
    if (!empty($sshStats['success_after_fail'])) {
        $lines[] = "[КРИТИЧНО] SSH компрометація:";
        foreach (array_slice($sshStats['success_after_fail'],0,5,true) as $ip=>$d)
            $lines[] = "  * {$ip} — {$d['fail']} невдалих → {$d['success']} успішних";
        $lines[] = "";
    }
    if (($sshStats['total_fail']??0) > 0) $lines[] = "SSH Brute-force: ".number_format($sshStats['total_fail']??0)." невдалих спроб";
    if (($sshStats['total_success']??0) > 0) $lines[] = "SSH Вдалі входи: ".($sshStats['total_success']??0);
    if ($ns) {
        $lines[] = ""; $lines[] = "HTTP аналіз:";
        $lines[] = "  SQLi: ".($ns['sqli_total']??0)."  XSS: ".($ns['xss_total']??0)."  Path: ".($ns['path_total']??0)."  Scan: ".($ns['scan_total']??0);
        if (!empty($ns['risk_scores'])) { $lines[] = "  Топ Risk Score:"; foreach (array_slice($ns['risk_scores'],0,5,true) as $ip=>$risk) $lines[] = "    * {$ip} — {$risk}/100"; }
        if (!empty($analysis['httpTopIps'])) { $lines[] = "  Топ-10 IP:"; $i=0; foreach (array_slice($analysis['httpTopIps'],0,10,true) as $ip=>$cnt) $lines[] = "    ".(++$i).". {$ip} — ".number_format($cnt)." запитів"; }
    }
    if ($ms) {
        $lines[] = ""; $lines[] = "Mail аналіз:";
        $lines[] = "  SMTP AUTH fail: ".number_format($ms['total_auth_fail']??0);
        if (!empty($ms['auth_fail_ips'])) { $lines[] = "  Зловмисники:"; foreach (array_slice($ms['auth_fail_ips'],0,5,true) as $ip=>$cnt) $lines[] = "    * {$ip} — {$cnt}"; }
        if (!empty($ms['top_ips'])) { $lines[] = "  Топ-10 IP листів:"; $i=0; foreach (array_slice($ms['top_ips'],0,10,true) as $ip=>$cnt) $lines[] = "    ".(++$i).". {$ip} — {$cnt} листів"; }
    }
    $body = implode("\n", $lines);

    // ── HTML звіт ──
    $e = fn($s) => htmlspecialchars((string)$s, ENT_QUOTES);
    $genTime = date('d.m.Y H:i:s');
    $h  = '<!DOCTYPE html><html lang="uk"><head><meta charset="UTF-8"><style>';
    $h .= 'body{font-family:Arial,sans-serif;font-size:13px;color:#222;background:#f4f6fb;margin:0;padding:0}';
    $h .= '.wrap{max-width:960px;margin:0 auto;padding:24px}';
    $h .= '.hdr{background:linear-gradient(135deg,#1a3a6b,#2563b0);color:#fff;padding:22px 26px;border-radius:10px;margin-bottom:18px}';
    $h .= '.hdr h1{margin:0 0 4px;font-size:1.25rem}.hdr .sub{opacity:.8;font-size:.8rem}';
    $h .= '.sec{background:#fff;border-radius:8px;border:1px solid #dde3f0;margin-bottom:14px;overflow:hidden}';
    $h .= '.stitle{background:#f0f4fb;padding:8px 14px;font-weight:700;font-size:.82rem;color:#1a3a6b;border-bottom:1px solid #dde3f0}';
    $h .= '.sbody{padding:10px 14px}';
    $h .= 'table{width:100%;border-collapse:collapse;font-size:.77rem}';
    $h .= 'th{background:#f0f4fb;padding:6px 9px;text-align:left;font-weight:700;color:#1a3a6b;border-bottom:2px solid #dde3f0}';
    $h .= 'td{padding:5px 9px;border-bottom:1px solid #eef0f5}';
    $h .= '.kpi-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:8px;padding:10px 14px}';
    $h .= '.kpi{background:#f0f4fb;border-radius:6px;padding:9px;text-align:center}';
    $h .= '.kv{font-size:1.4rem;font-weight:800;line-height:1}.kl{font-size:.67rem;color:#666;margin-top:2px}';
    $h .= '.crit{background:#fde8e8!important}.warn{background:#fff8e1!important}';
    $h .= '.bar-w{background:#eee;border-radius:3px;height:6px;width:90px;display:inline-block;vertical-align:middle;margin-left:5px}';
    $h .= '.bar-f{height:6px;border-radius:3px}';
    $h .= '.footer{text-align:center;font-size:.68rem;color:#aaa;margin-top:14px}';
    $h .= '</style></head><body><div class="wrap">';
    $h .= '<div class="hdr"><h1>🛡 LogPortal — Звіт загроз</h1><div class="sub">Сервер: <b>'.$e($srv['name']).'</b> &nbsp;·&nbsp; '.$e($genTime).'</div></div>';

    // KPI
    $kpis = [['SSH компрометація',count($sshStats['success_after_fail']??[]),'#d32f2f'],['SSH brute-force',$sshStats['total_fail']??0,'#f57c00'],['SSH входи',$sshStats['total_success']??0,'#1565c0'],['SQLi',$ns['sqli_total']??0,'#f57c00'],['XSS',$ns['xss_total']??0,'#7b1fa2'],['SMTP AUTH fail',$ms['total_auth_fail']??0,'#c62828']];
    $h .= '<div class="sec"><div class="stitle">📊 Зведення</div><div class="kpi-grid">';
    foreach ($kpis as [$lbl,$val,$clr]) $h .= '<div class="kpi"><div class="kv" style="color:'.($val>0?$clr:'#388e3c').'">'.$e($val).'</div><div class="kl">'.$e($lbl).'</div></div>';
    $h .= '</div></div>';

    // SSH компрометація
    if (!empty($sshStats['success_after_fail'])) {
        $h .= '<div class="sec"><div class="stitle">🔴 SSH Компрометація</div><div class="sbody"><table><tr><th>IP</th><th>Невдалих</th><th>Успішних</th></tr>';
        foreach ($sshStats['success_after_fail'] as $ip=>$d) $h .= '<tr class="crit"><td><b>'.$e($ip).'</b></td><td style="color:#d32f2f;font-weight:700">'.$d['fail'].'</td><td style="color:#d32f2f;font-weight:700">'.$d['success'].'</td></tr>';
        $h .= '</table></div></div>';
    }
    // SSH brute-force
    if (!empty($sshStats['fail_ips'])) {
        $h .= '<div class="sec"><div class="stitle">🔑 SSH Brute-force — топ IP</div><div class="sbody"><table><tr><th>IP</th><th>Невдалих</th></tr>';
        foreach (array_slice($sshStats['fail_ips'],0,10,true) as $ip=>$cnt) $h .= '<tr'.($cnt>1000?' class="crit"':($cnt>100?' class="warn"':'')).'>'.  '<td><b>'.$e($ip).'</b></td><td>'.number_format($cnt).'</td></tr>';
        $h .= '</table></div></div>';
    }
    // HTTP Risk Score
    if ($ns && !empty($ns['risk_scores'])) {
        $h .= '<div class="sec"><div class="stitle">🎯 HTTP Risk Score — топ IP</div><div class="sbody"><table><tr><th>IP</th><th>Risk</th><th>SQLi</th><th>XSS</th><th>Path</th><th>Scan</th><th>Запити</th></tr>';
        foreach (array_slice($ns['risk_scores'],0,15,true) as $ip=>$risk) {
            $clr=$risk>=70?'#d32f2f':($risk>=40?'#f57c00':'#388e3c'); $rc=$risk>=70?' class="crit"':($risk>=40?' class="warn"':'');
            $bar='<div class="bar-w"><div class="bar-f" style="width:'.min(100,$risk).'%;background:'.$clr.'"></div></div>';
            $h .= '<tr'.$rc.'><td><b>'.$e($ip).'</b></td><td><span style="color:'.$clr.';font-weight:700">'.$risk.'</span>'.$bar.'</td><td>'.($ns['sqli_by_ip'][$ip]??0).'</td><td>'.($ns['xss_by_ip'][$ip]??0).'</td><td>'.($ns['path_by_ip'][$ip]??0).'</td><td>'.($ns['scan_by_ip'][$ip]??0).'</td><td>'.number_format($ns['top_ips'][$ip]??0).'</td></tr>';
        }
        $h .= '</table></div></div>';
    }
    // HTTP Топ-10 IP
    if (!empty($analysis['httpTopIps'])) {
        $maxB=max(array_values($analysis['httpTopIps'])?:[1]);
        $h .= '<div class="sec"><div class="stitle">🌐 HTTP — Топ-10 IP за запитами</div><div class="sbody"><table><tr><th>#</th><th>IP</th><th>Запитів</th><th>Трафік</th></tr>';
        $i=1; foreach (array_slice($analysis['httpTopIps'],0,10,true) as $ip=>$cnt) {
            $b=$analysis['httpTrafficByIp'][$ip]??($ns['bw_by_ip'][$ip]??0);
            $bs=$b>=1048576?round($b/1048576,1).' MB':($b>=1024?round($b/1024).' KB':$b.' B');
            $h .= '<tr><td>'.(++$i).'</td><td><b>'.$e($ip).'</b></td><td>'.number_format($cnt).'</td><td>'.$e($bs).'</td></tr>';
        }
        $h .= '</table></div></div>';
    }
    // SMTP
    if ($ms && !empty($ms['auth_fail_ips'])) {
        $h .= '<div class="sec"><div class="stitle">📧 SMTP AUTH Brute-force</div><div class="sbody">';
        if (!empty($ms['outbound_spike'])) $h .= '<div style="background:#fde8e8;padding:6px 10px;border-radius:4px;margin-bottom:7px;font-size:.77rem">⚠ Сплеск: макс.'.($ms['hour_max']??0).'/год (середнє '.($ms['hour_avg']??0).'/год)</div>';
        $h .= '<table><tr><th>IP</th><th>Невдалих AUTH</th></tr>';
        foreach (array_slice($ms['auth_fail_ips'],0,10,true) as $ip=>$cnt) $h .= '<tr'.($cnt>500?' class="crit"':($cnt>50?' class="warn"':'')).'>'.  '<td><b>'.$e($ip).'</b></td><td>'.number_format($cnt).'</td></tr>';
        $h .= '</table></div></div>';
    }
    // Mail Топ-10 IP
    if ($ms && !empty($ms['top_ips'])) {
        $h .= '<div class="sec"><div class="stitle">📬 Mail — Топ-10 IP за листами</div><div class="sbody"><table><tr><th>#</th><th>IP</th><th>Листів</th><th>Трафік</th></tr>';
        $i=1; foreach (array_slice($ms['top_ips'],0,10,true) as $ip=>$cnt) {
            $b=$ms['traffic_by_ip'][$ip]??0;
            $bs=$b>=1048576?round($b/1048576,1).' MB':($b>=1024?round($b/1024).' KB':$b.' B');
            $h .= '<tr><td>'.(++$i).'</td><td><b>'.$e($ip).'</b></td><td>'.number_format($cnt).'</td><td>'.$e($bs).'</td></tr>';
        }
        $h .= '</table></div></div>';
    }
    $h .= '<div class="footer">LogPortal v2.1.0 &nbsp;·&nbsp; '.$e($genTime).'</div></div></body></html>';

    $subject = "[LogPortal] Звіт загроз: {$srv['name']} " . date('d.m.Y H:i');
    $ok = sendEmailAlert($smtpHost,$smtpPort,$smtpUser,$smtpPass,$smtpFrom,$alertTo,$subject,$body,$h);
    echo json_encode(['ok'=>$ok,'error'=>$ok?'':'Не вдалось відправити. Перевірте SMTP налаштування.']);
    exit;
}

if (!function_exists('statusBadge')) {
function statusBadge(int $s): string {
    $cls = $s>=500?'badge-crit':($s>=400?'badge-warn':'badge-ok');
    return "<span class=\"{$cls}\">{$s}</span>";
}
}
?>
<!DOCTYPE html><html lang="uk"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Загрози — LogPortal</title>
<link rel="stylesheet" href="css/style.css">
</head><body>
<?php renderGovStrip(); renderHeader($user); renderNav($user, 'threats', $sid); ?>
<main class="main-content"><div class="container">

<div class="page-header" style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px">
  <div>
    <h1 class="page-title">🛡 Дашборд загроз</h1>
    <div class="page-subtitle">Risk Score · GeoIP · Кореляція · Алерти</div>
  </div>
  <button id="btnSendAlert" class="tg-btn" style="display:none">📧 Надіслати Email звіт</button>
</div>

<div id="alertBox" style="display:none"></div>

<!-- Вибір сервера -->
<div class="srv-select">
  <label style="font-weight:600;font-size:.85rem">🖥 Сервер:</label>
  <form method="get" style="display:flex;gap:8px;align-items:center">
    <select name="sid" onchange="this.form.submit()">
      <option value="">— оберіть сервер —</option>
      <?php foreach ($servers as $s): ?>
      <option value="<?= $s['id'] ?>" <?= $s['id']==$sid?'selected':'' ?>>
        <?= htmlspecialchars($s['name']) ?> (<?= htmlspecialchars($s['host']) ?>)
      </option>
      <?php endforeach; ?>
    </select>
    <button type="submit" class="btn-primary" style="padding:7px 16px;font-size:.82rem">Завантажити</button>
  </form>
  <?php if (!$smtpHost || !$alertTo): ?>
  <span style="font-size:.78rem;color:#999">⚠ Email не налаштовано —
    <a href="admin.php" style="color:var(--blue-main)">Адмін → Налаштування</a></span>
  <?php endif; ?>
</div>

<?php if (!$srv): ?>
<div class="no-data">Оберіть сервер для аналізу загроз</div>
<?php elseif (!$sshStats): ?>
<div class="no-data">⚠ Не вдалось підключитись до сервера</div>
<?php else:
    $ss      = $sshStats;
    $critSsh = count($ss['success_after_fail'] ?? []);
    $sshFail = $ss['total_fail'] ?? 0;
    $sshSuccCount = count($ss['success_ips'] ?? []);
?>

<!-- ════════════════════════════════════════════════════
     Вибір файлів для HTTP та Mail аналізу
     ════════════════════════════════════════════════════ -->
<div class="file-picker-block" id="filePicker">
  <div class="file-picker-title">📂 Вибір файлів для аналізу вразливостей
    <button class="tg-btn" id="btnLoadFiles" onclick="loadThreatFiles()" style="margin-left:auto;padding:5px 14px;font-size:.78rem">🔄 Завантажити список файлів</button>
  </div>
  <div id="filePickerContent">
    <div style="font-size:.8rem;color:#999">Натисніть «Завантажити список файлів» для отримання переліку лог-файлів з сервера</div>
  </div>
  <div id="analyzeBar" class="analyze-bar" style="display:none;margin-top:14px;padding-top:12px;border-top:1px solid var(--gray-border)">
    <button class="tg-btn" id="btnAnalyze" onclick="runAnalysis()">🔍 Аналізувати вибрані файли</button>
    <span id="analyzeStatus" style="font-size:.8rem;color:#666"></span>
  </div>
</div>

<!-- ── SSH картки ── -->
<div class="threat-grid" id="summaryGrid">
  <div class="threat-card <?= $critSsh ? 'critical' : 'low' ?>">
    <div class="threat-title">SSH Компрометація</div>
    <div class="threat-val" style="color:<?= $critSsh?'#d32f2f':'#388e3c' ?>"><?= $critSsh ?></div>
    <div class="threat-sub">IP з успішним входом після brute-force</div>
  </div>
  <div class="threat-card <?= $sshFail>1000?'high':($sshFail>100?'medium':'low') ?>">
    <div class="threat-title">SSH Brute-force</div>
    <div class="threat-val"><?= number_format($sshFail) ?></div>
    <div class="threat-sub">невдалих спроб входу</div>
  </div>
  <div class="threat-card <?= $sshSuccCount>0?'medium':'low' ?>">
    <div class="threat-title">SSH Вдалі входи</div>
    <div class="threat-val" style="color:<?= $sshSuccCount>0?'#1565c0':'#388e3c' ?>"><?= $ss['total_success']??0 ?></div>
    <div class="threat-sub"><?= $sshSuccCount ?> унікальних IP</div>
  </div>
  <!-- HTTP/Mail картки — заповнюються JS після аналізу -->
  <div class="threat-card low" id="card-sqli">
    <div class="threat-title">SQLi атаки</div>
    <div class="threat-val" style="color:#aaa">—</div>
    <div class="threat-sub">оберіть HTTP файли</div>
  </div>
  <div class="threat-card low" id="card-xss">
    <div class="threat-title">XSS атаки</div>
    <div class="threat-val" style="color:#aaa">—</div>
    <div class="threat-sub">оберіть HTTP файли</div>
  </div>
  <div class="threat-card low" id="card-smtp">
    <div class="threat-title">SMTP AUTH Brute-force</div>
    <div class="threat-val" style="color:#aaa">—</div>
    <div class="threat-sub">оберіть Mail файли</div>
  </div>
</div>

<!-- Результати HTTP/Mail аналізу -->
<div id="results-section"></div>

<!-- SSH таблиці -->
<?php if (!empty($ss['success_after_fail'])): ?>
<div class="section-title">🔴 Критично — SSH компрометація</div>
<table class="tbl">
  <tr><th>IP</th><th>Країна</th><th>Невдалих</th><th>Успішних</th><th>Статус</th></tr>
  <?php foreach ($ss['success_after_fail'] as $ip => $d):
    $geo = $geoData[$ip] ?? []; ?>
  <tr style="background:#fde8e8">
    <td><b><?= htmlspecialchars($ip) ?></b></td>
    <td><?= $geo['countryCode']??'' ?> <?= htmlspecialchars($geo['city']??'') ?></td>
    <td style="color:#d32f2f;font-weight:700"><?= $d['fail'] ?></td>
    <td style="color:#d32f2f;font-weight:700"><?= $d['success'] ?></td>
    <td><span class="badge-crit">⚠ СКОМПРОМЕТОВАНО</span></td>
  </tr>
  <?php endforeach; ?>
</table>
<?php endif; ?>

<?php if (!empty($ss['success_ips'])): ?>
<div class="section-title">✅ SSH Вдалі входи — топ IP</div>
<table class="tbl">
  <tr><th>IP</th><th>Країна</th><th>Входів</th><th>Тип</th><th>Статус</th></tr>
  <?php foreach ($ss['success_ips'] as $ip => $cnt):
    $geo = $geoData[$ip] ?? [];
    $isLocal   = str_starts_with($ip,'10.')||str_starts_with($ip,'192.168.')||str_starts_with($ip,'172.');
    $isSuspect = isset($ss['success_after_fail'][$ip]);
    $rowCls    = $isSuspect?' class="row-crit"':($isLocal?'':' class="row-warn"'); ?>
  <tr<?= $rowCls ?>>
    <td><b><?= htmlspecialchars($ip) ?></b></td>
    <td><?= $geo['countryCode']??'' ?> <?= htmlspecialchars($geo['city']??'') ?></td>
    <td><span class="<?= $cnt>50?'badge-warn':'badge-ok' ?>"><?= number_format($cnt) ?></span></td>
    <td><span style="font-size:.75rem;color:#555"><?= $isLocal?'🏠 Локальна':'🌐 Зовнішній' ?></span></td>
    <td><?= $isSuspect?'<span class="badge-crit">⚠ після brute-force</span>':'<span class="badge-ok">OK</span>' ?></td>
  </tr>
  <?php endforeach; ?>
</table>
<?php endif; ?>

<?php if (!empty($ss['fail_ips'])): ?>
<div class="section-title">🔑 SSH Brute-force — топ IP</div>
<table class="tbl">
  <tr><th>IP</th><th>Країна</th><th>Невдалих спроб</th><th>Статус</th></tr>
  <?php foreach (array_slice($ss['fail_ips'],0,20,true) as $ip => $cnt):
    $geo = $geoData[$ip] ?? [];
    $lbl = $cnt>1000?'badge-crit':($cnt>100?'badge-warn':'badge-ok'); ?>
  <tr>
    <td><b><?= htmlspecialchars($ip) ?></b></td>
    <td><?= $geo['countryCode']??'' ?> <?= htmlspecialchars($geo['city']??'') ?></td>
    <td><span class="<?= $lbl ?>"><?= number_format($cnt) ?></span></td>
    <td><?= isset($ss['success_after_fail'][$ip])?'<span class="badge-crit">⚠ ВХІД УСПІШНИЙ</span>':'' ?></td>
  </tr>
  <?php endforeach; ?>
</table>
<?php endif; ?>

<?php endif; // sshStats ?>
</div></main>
<?php renderFooter(); ?>

<script>
const SID  = <?= (int)$sid ?>;
const SMTP_OK = <?= ($smtpHost && $alertTo) ? 'true' : 'false' ?>;

// ── Завантаження списку файлів ──
async function loadThreatFiles() {
    const btn = document.getElementById('btnLoadFiles');
    btn.disabled = true; btn.textContent = '⏳ Завантаження…';
    const content = document.getElementById('filePickerContent');
    content.innerHTML = '<div class="picker-loading"><span class="spin"></span> Сканування файлів на сервері…</div>';
    try {
        const r = await fetch(`api.php?action=list_threat_files&sid=${SID}`);
        const d = await r.json();
        if (d.error) { content.innerHTML = `<div class="alert-box error">❌ ${esc(d.error)}</div>`; return; }
        renderFilePicker(d.http || [], d.mail || []);
        document.getElementById('analyzeBar').style.display = 'flex';
    } catch(e) {
        content.innerHTML = `<div class="alert-box error">❌ Помилка з'єднання: ${esc(e.message)}</div>`;
    } finally {
        btn.disabled = false; btn.textContent = '🔄 Оновити список';
    }
}

function fmtSz(b) {
    if (b>=1073741824) return (b/1073741824).toFixed(2)+' GB';
    if (b>=1048576)    return (b/1048576).toFixed(1)+' MB';
    if (b>=1024)       return Math.round(b/1024)+' KB';
    return b+' B';
}

function renderFilePicker(httpFiles, mailFiles) {
    const content = document.getElementById('filePickerContent');
    let html = '<div class="file-picker-grid">';

    // HTTP
    html += '<div>';
    html += '<div class="file-picker-title" style="margin-bottom:6px">🌐 HTTP логи (Nginx/Apache)';
    if (httpFiles.length) html += `<button class="sel-all-btn" onclick="toggleAll('http', true)">Вибрати всі</button>`;
    html += '</div>';
    if (!httpFiles.length) {
        html += '<div class="picker-loading">Файли не знайдено</div>';
    } else {
        html += '<div class="file-list-box">';
        let lastDir = null;
        httpFiles.forEach((f, i) => {
            if (f.dir !== lastDir) {
                html += `<div class="fp-sub">${esc(f.dir)}</div>`;
                lastDir = f.dir;
            }
            html += `<label class="file-item">
                <input type="checkbox" class="http-file" value="${esc(f.path)}">
                <span class="file-item-name">${esc(f.name)}</span>
                <span class="file-item-sz">${fmtSz(f.size)}</span>
            </label>`;
        });
        html += '</div>';
    }
    html += '</div>';

    // Mail
    html += '<div>';
    html += '<div class="file-picker-title" style="margin-bottom:6px">📧 Mail логи (Postfix)';
    if (mailFiles.length) html += `<button class="sel-all-btn" onclick="toggleAll('mail', true)">Вибрати всі</button>`;
    html += '</div>';
    if (!mailFiles.length) {
        html += '<div class="picker-loading">Файли не знайдено</div>';
    } else {
        html += '<div class="file-list-box">';
        let lastDir2 = null;
        mailFiles.forEach((f, i) => {
            if (f.dir !== lastDir2) {
                html += `<div class="fp-sub">${esc(f.dir)}</div>`;
                lastDir2 = f.dir;
            }
            html += `<label class="file-item">
                <input type="checkbox" class="mail-file" value="${esc(f.path)}">
                <span class="file-item-name">${esc(f.name)}</span>
                <span class="file-item-sz">${fmtSz(f.size)}</span>
            </label>`;
        });
        html += '</div>';
    }
    html += '</div>';

    html += '</div>'; // grid
    content.innerHTML = html;
}

function toggleAll(type, check) {
    document.querySelectorAll(`.${type}-file`).forEach(cb => cb.checked = check);
}

// ── Запуск аналізу ──
async function runAnalysis() {
    const httpFiles = [...document.querySelectorAll('.http-file:checked')].map(c => c.value);
    const mailFiles = [...document.querySelectorAll('.mail-file:checked')].map(c => c.value);
    if (!httpFiles.length && !mailFiles.length) {
        showAlert('info', 'ℹ Оберіть хоча б один файл для аналізу');
        return;
    }
    const btn = document.getElementById('btnAnalyze');
    const status = document.getElementById('analyzeStatus');
    btn.disabled = true;
    status.innerHTML = '<span class="spin"></span> Зчитування та аналіз файлів…';
    document.getElementById('results-section').innerHTML = '<div class="results-loading"><span class="spin"></span> Аналіз…</div>';

    try {
        const fd = new FormData();
        fd.append('sid',        SID);
        fd.append('http_files', JSON.stringify(httpFiles));
        fd.append('mail_files', JSON.stringify(mailFiles));
        const r  = await fetch('api.php?action=analyze_threats', {method:'POST', body:fd});
        const d  = await r.json();
        if (d.error) { showAlert('error', '❌ ' + d.error); document.getElementById('results-section').innerHTML=''; return; }
        renderResults(d);
        if (SMTP_OK) {
            document.getElementById('btnSendAlert').style.display = 'inline-block';
            window._lastAnalysis = d;
        }
    } catch(e) {
        showAlert('error', '❌ Помилка: ' + e.message);
        document.getElementById('results-section').innerHTML = '';
    } finally {
        btn.disabled = false;
        status.textContent = '';
    }
}

// ── Рендер результатів ──
function renderResults(d) {
    const ns = d.nginxStats;
    const ms = d.smtpStats;
    let html = '';

    // Оновити картки
    if (ns) {
        setCard('card-sqli', 'SQLi атаки',  ns.sqli_total||0, 'спроб SQL ін\'єкції', ns.sqli_total>0?'high':'low', ns.sqli_total>0?'#f57c00':'#388e3c');
        setCard('card-xss',  'XSS атаки',   ns.xss_total||0,  'спроб XSS',           ns.xss_total>0?'medium':'low');
    }
    if (ms) {
        setCard('card-smtp','SMTP AUTH Brute-force', ms.total_auth_fail||0, 'невдалих AUTH', ms.total_auth_fail>100?'high':'low');
    }

    // ── HTTP: Risk Score ──
    if (ns && ns.risk_scores && Object.keys(ns.risk_scores).length) {
        html += secTitle('🎯 HTTP — Risk Score (топ загрозливих IP)');
        html += '<table class="tbl"><tr><th>IP</th><th>Risk</th><th>SQLi</th><th>XSS</th><th>Path</th><th>Scan</th><th>Запити</th></tr>';
        const rs = Object.entries(ns.risk_scores).slice(0,15);
        rs.forEach(([ip, risk]) => {
            const rcls = risk>=70?'badge-crit':(risk>=40?'badge-warn':'badge-ok');
            html += `<tr><td><b>${esc(ip)}</b></td>
                <td><span class="${rcls}">${risk}/100</span>
                    <div class="risk-bar-wrap"><div class="risk-bar ${riskCls(risk)}" style="width:${risk}%"></div></div></td>
                <td>${ns.sqli_by_ip?.[ip]||0}</td>
                <td>${ns.xss_by_ip?.[ip]||0}</td>
                <td>${ns.path_by_ip?.[ip]||0}</td>
                <td>${ns.scan_by_ip?.[ip]||0}</td>
                <td>${fmt(ns.top_ips?.[ip]||0)}</td></tr>`;
        });
        html += '</table>';
    }

    // ── HTTP: Топ-10 IP за кількістю запитів ──
    if (d.httpTopIps && Object.keys(d.httpTopIps).length) {
        html += secTitle('🌐 HTTP — Топ-10 IP за запитами');
        html += '<table class="tbl"><tr><th>#</th><th>IP</th><th>Запитів</th><th>Трафік</th></tr>';
        let i=1;
        Object.entries(d.httpTopIps).forEach(([ip, cnt]) => {
            const bytes = d.httpTrafficByIp?.[ip] || (ns?.bw_by_ip?.[ip]||0);
            html += `<tr><td>${i++}</td><td><b>${esc(ip)}</b></td><td>${fmt(cnt)}</td><td>${fmtB(bytes)}</td></tr>`;
        });
        html += '</table>';
    }

    // ── HTTP: Трафік по IP ──
    if (ns && ns.bw_by_ip && Object.keys(ns.bw_by_ip).length) {
        html += secTitle('📊 HTTP — Трафік по IP (топ-10)');
        const entries = Object.entries(ns.bw_by_ip).slice(0,10);
        const maxBytes = entries[0]?.[1] || 1;
        html += '<table class="tbl"><tr><th>#</th><th>IP</th><th>Трафік</th><th>Розподіл</th></tr>';
        entries.forEach(([ip, bytes], i) => {
            const pct = Math.round(bytes/maxBytes*100);
            html += `<tr><td>${i+1}</td><td><b>${esc(ip)}</b></td><td>${fmtB(bytes)}</td>
                <td><div style="background:#e8f0fe;border-radius:3px;height:10px;width:120px;display:inline-block">
                    <div style="background:#2196F3;height:10px;border-radius:3px;width:${pct}%"></div></div></td></tr>`;
        });
        html += '</table>';
    }

    // ── HTTP: Path Traversal ──
    if (ns && ns.path_hits && ns.path_hits.length) {
        html += secTitle('📁 Path Traversal / Config Probe');
        html += '<table class="tbl"><tr><th>IP</th><th>Час</th><th>Метод</th><th>URI</th><th>Статус</th><th>Тип</th></tr>';
        ns.path_hits.slice(0,25).forEach(h => {
            html += `<tr><td>${esc(h[0])}</td><td style="white-space:nowrap;font-size:.72rem">${esc(h[1])}</td>
                <td>${esc(h[2])}</td><td style="font-family:monospace;font-size:.7rem;word-break:break-all">${esc(h[3])}</td>
                <td>${stBadge(h[4])}</td><td><span class="badge-warn">${esc(h[5])}</span></td></tr>`;
        });
        html += '</table>';
    }

    // ── HTTP: Сканери ──
    if (ns && ns.scan_hits && ns.scan_hits.length) {
        html += secTitle('🔍 Виявлені сканери');
        html += '<table class="tbl"><tr><th>IP</th><th>Час</th><th>URI</th><th>Статус</th><th>Інструмент</th></tr>';
        ns.scan_hits.slice(0,20).forEach(h => {
            html += `<tr><td>${esc(h[0])}</td><td style="white-space:nowrap;font-size:.72rem">${esc(h[1])}</td>
                <td style="font-family:monospace;font-size:.7rem;word-break:break-all">${esc(h[3])}</td>
                <td>${stBadge(h[4])}</td><td><span class="badge-warn">${esc(h[5])}</span></td></tr>`;
        });
        html += '</table>';
    }

    // ── Mail: AUTH Brute-force ──
    if (ms && ms.auth_fail_ips && Object.keys(ms.auth_fail_ips).length) {
        html += secTitle('📧 SMTP AUTH Brute-force — топ IP');
        if (ms.outbound_spike)
            html += `<div class="alert-box error">⚠ Аномальний сплеск вихідних листів: макс. ${ms.hour_max}/год (середнє ${ms.hour_avg}/год)</div>`;
        html += '<table class="tbl"><tr><th>IP</th><th>Невдалих AUTH</th></tr>';
        Object.entries(ms.auth_fail_ips).forEach(([ip, cnt]) => {
            const lbl = cnt>500?'badge-crit':(cnt>50?'badge-warn':'badge-ok');
            html += `<tr><td><b>${esc(ip)}</b></td><td><span class="${lbl}">${fmt(cnt)}</span></td></tr>`;
        });
        html += '</table>';
    }

    // ── Mail: Топ-10 IP за листами ──
    if (ms && ms.top_ips && Object.keys(ms.top_ips).length) {
        html += secTitle('📬 Mail — Топ-10 IP за кількістю листів');
        html += '<table class="tbl"><tr><th>#</th><th>IP</th><th>Листів</th><th>Трафік</th></tr>';
        let i=1;
        Object.entries(ms.top_ips).forEach(([ip, cnt]) => {
            const bytes = ms.traffic_by_ip?.[ip]||0;
            html += `<tr><td>${i++}</td><td><b>${esc(ip)}</b></td><td>${fmt(cnt)}</td><td>${fmtB(bytes)}</td></tr>`;
        });
        html += '</table>';
    }

    // ── Mail: Трафік по IP ──
    if (ms && ms.traffic_by_ip && Object.keys(ms.traffic_by_ip).length) {
        html += secTitle('📊 Mail — Трафік по IP (топ-10)');
        const entries = Object.entries(ms.traffic_by_ip).slice(0,10);
        const maxBytes = entries[0]?.[1]||1;
        html += '<table class="tbl"><tr><th>#</th><th>IP</th><th>Трафік</th><th>Розподіл</th></tr>';
        entries.forEach(([ip,bytes],i) => {
            const pct = Math.round(bytes/maxBytes*100);
            html += `<tr><td>${i+1}</td><td><b>${esc(ip)}</b></td><td>${fmtB(bytes)}</td>
                <td><div style="background:#fce4ec;border-radius:3px;height:10px;width:120px;display:inline-block">
                    <div style="background:#e91e63;height:10px;border-radius:3px;width:${pct}%"></div></div></td></tr>`;
        });
        html += '</table>';
    }

    if (!html) html = '<div class="no-data">Загроз не виявлено у вибраних файлах</div>';
    document.getElementById('results-section').innerHTML = html;
}

// ── Helpers ──
function esc(s){ const d=document.createElement('div');d.textContent=String(s||'');return d.innerHTML; }
function fmt(n){ return Number(n).toLocaleString('uk-UA'); }
function fmtB(b){ b=Number(b||0);if(b>=1073741824)return(b/1073741824).toFixed(2)+' GB';if(b>=1048576)return(b/1048576).toFixed(1)+' MB';if(b>=1024)return Math.round(b/1024)+' KB';return b+' B'; }
function riskCls(r){ return r>=70?'risk-critical':(r>=40?'risk-high':'risk-medium'); }
function stBadge(s){ s=parseInt(s||0);const c=s>=500?'#d32f2f':(s>=400?'#f57c00':'#388e3c');return `<span style="background:${c};color:#fff;padding:1px 7px;border-radius:8px;font-size:.7rem">${s}</span>`; }
function secTitle(t){ return `<div class="section-title">${t}</div>`; }
function setCard(id, title, val, sub, severity, color='') {
    const el = document.getElementById(id); if(!el) return;
    el.className = `threat-card ${severity}`;
    el.innerHTML = `<div class="threat-title">${title}</div>
        <div class="threat-val"${color?` style="color:${color}"`:``}>${fmt(val)}</div>
        <div class="threat-sub">${sub}</div>`;
}
function showAlert(type, msg) {
    const el = document.getElementById('alertBox');
    el.className = `alert-box ${type}`;
    el.textContent = msg;
    el.style.display='block';
    setTimeout(()=>el.style.display='none', 5000);
}

// Email alert
document.getElementById('btnSendAlert')?.addEventListener('click', async () => {
    if (!window._lastAnalysis) return;
    const btn = document.getElementById('btnSendAlert');
    btn.disabled=true; btn.textContent='⏳ Відправка…';
    try {
        const fd=new FormData();
        fd.append('sid', SID);
        fd.append('send_alert','1');
        fd.append('analysis_json', JSON.stringify(window._lastAnalysis));
        const r=await fetch('threats.php?sid='+SID+'&email_only=1',{method:'POST',body:fd});
        const d=await r.json();
        showAlert(d.ok?'success':'error', d.ok?'✅ Email надіслано!':'❌ '+d.error);
    } finally { btn.disabled=false; btn.textContent='📧 Надіслати Email звіт'; }
});
</script>
</body></html>
