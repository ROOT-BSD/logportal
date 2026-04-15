<?php
require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/layout.php';
require_once __DIR__ . '/includes/ssh.php';
require_once __DIR__ . '/includes/postfix_parser.php';
require_once __DIR__ . '/includes/filters.php';
requireAuth();
sendSecurityHeaders();
@set_time_limit(300);
$user = currentUser();
$db   = getDB();

$sid = (int)($_GET['sid'] ?? 0);
if (!$sid) { header('Location: servers.php'); exit; }

$st = $db->prepare("SELECT * FROM servers WHERE id=? AND user_id=?");
$st->execute([$sid, $user['id']]);
$srv = $st->fetch();
if (!$srv) { header('Location: servers.php'); exit; }

// Отримуємо список файлів з GET або шукаємо mail-логи автоматично
$files = $_GET['files'] ?? [];
if (empty($files) && !empty($_GET['file'])) $files = [$_GET['file']];
$files = array_filter(array_map('trim', (array)$files));

// Фільтр по датах
$dateFrom = $_GET['date_from'] ?? '';
$dateTo   = $_GET['date_to']   ?? '';
$tsFrom   = $dateFrom ? strtotime($dateFrom . ' 00:00:00') : 0;
$tsTo     = $dateTo   ? strtotime($dateTo   . ' 23:59:59') : PHP_INT_MAX;

$err    = '';
$msgs   = [];
$parsed = [];
$stats  = null;

if (!empty($files)) {
    $conn = sshConnect($srv);
    if (!$conn['success']) {
        $err = $conn['error'] ?? 'Помилка підключення SSH';
    } else {
        $allRaw = '';
        foreach ($files as $file) {
            $isGz = str_ends_with(strtolower($file), '.gz');
            if ($isGz) {
                $zcatBin = trim(sshExec($conn, 'which zcat 2>/dev/null || which gzip 2>/dev/null'));
                if (empty($zcatBin)) continue;
                $zcmd = str_ends_with($zcatBin, 'gzip') ? 'gzip -dc' : 'zcat';
                $raw  = sshExec($conn, "$zcmd " . escapeshellarg($file) . " 2>/dev/null");
            } else {
                $sz  = (int)trim(sshExec($conn, "wc -c " . escapeshellarg($file) . " 2>/dev/null | awk '{print \$1}'"));
                $raw = sshExec($conn, ($sz > 209715200 ? 'tail -n 2000000' : 'cat') . ' ' . escapeshellarg($file) . ' 2>/dev/null');
            }
            if (!empty(trim($raw))) {
                $allRaw .= $raw . "\n";
                $parsed[] = basename($file);
            }
        }

        if (empty(trim($allRaw))) {
            $err = 'Файли порожні або недоступні';
        } else {
            if ($tsFrom > 0 || $tsTo < PHP_INT_MAX)
                $allRaw = filterByDate($allRaw, 'postfix', $tsFrom, $tsTo, $hintYear);

            // Визначаємо рік з шляху файлу (напр. /opt/log/postfix/2024/...)
            $hintYear = 0;
            foreach ($files as $file) {
                if (preg_match('~/(\d{4})/~', $file, $ym)) {
                    $y = (int)$ym[1];
                    if ($y >= 2000 && $y <= 2099) { $hintYear = $y; break; }
                }
            }

            $stats = parsePostfixLog($allRaw, 5000000, $hintYear);
            unset($allRaw);
            // Формуємо масив повідомлень
            foreach (($stats['messages'] ?? []) as $qid => $q) {
                if (!$q['from'] && empty($q['to'])) continue;
                $msgs[] = [
                    'qid'     => $qid,
                    'time'    => $q['time']    ?: 0,
                    'from'    => $q['from']    ?: '',
                    'to'      => $q['to']      ?: [],
                    'subject' => $q['subject'] ?: '',
                    'size'    => $q['size']    ?: 0,
                    'status'  => $q['status']  ?: '',
                    'delay'   => $q['delay']   ?: 0,
                    'dsn'     => $q['dsn']     ?: '',
                    'reason'  => $q['reason']  ?: '',
                    'xmailer' => $q['xmailer'] ?: '',
                ];
            }
            usort($msgs, fn($a,$b) => $b['time'] <=> $a['time']);
        }
    }
}


// Будуємо query string для посилань
$queryFiles = implode('&', array_map(fn($f) => 'files[]=' . urlencode($f), $files));
?>
<!DOCTYPE html>
<html lang="uk">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Пошук пошти — <?= htmlspecialchars($srv['name']) ?> — LogPortal</title>
<link rel="stylesheet" href="css/style.css">
<script>
(function(){var t=localStorage.getItem('lp_theme');if(t)document.documentElement.setAttribute('data-theme',t);})();
</script>
</head>
<body>
<div class="page-wrap">

<?php renderGovStrip(); renderHeader($user); renderNav($user, 'mail', $sid); ?>
<div class="breadcrumbs"><div class="container">
  <a href="servers.php">Сервери</a><span class="bc-sep">›</span>
  <a href="logs.php?sid=<?= $sid ?>"><?= htmlspecialchars($srv['name']) ?></a><span class="bc-sep">›</span>
  <span class="bc-current">Пошук пошти</span>
</div></div>

<main class="page-content"><div class="container">

<div class="page-title-block">
  <div class="page-title-text">
    <h1>✉ Пошук поштових повідомлень</h1>
    <div style="margin-top:4px;font-size:.82rem;color:var(--gray-mid)">
      🖥 <?= htmlspecialchars($srv['name']) ?>
      <?php foreach ($parsed as $f): ?>
        &nbsp;·&nbsp; 📄 <?= htmlspecialchars($f) ?>
      <?php endforeach; ?>
    </div>
  </div>
  <div class="flex gap-2">
    <a href="logs.php?sid=<?= $sid ?>" class="btn btn-outline btn-sm">← Назад</a>
    <?php if (!empty($files)): ?>
    <a href="analyze.php?sid=<?= $sid ?>&<?= $queryFiles ?>&date_from=<?= urlencode($dateFrom) ?>&date_to=<?= urlencode($dateTo) ?>"
       class="btn btn-outline btn-sm">📊 Повний аналіз</a>
    <?php endif; ?>
  </div>
</div>

<?php if ($err): ?>
<div class="alert alert-error"><span class="alert-icon">✕</span> <?= htmlspecialchars($err) ?></div>

<?php elseif (empty($files)): ?>
<!-- ── Форма вибору файлів ── -->
<div class="card" style="max-width:780px">
  <div class="card-header"><div class="card-header-title">📂 Оберіть лог-файли</div></div>
  <div class="card-body" style="padding:20px">
    <?php
    $conn2    = sshConnect($srv);
    $mailFiles = $conn2['success'] ? getMailLogFiles($conn2) : [];
    // Групуємо по директоріях
    $byDir = [];
    foreach ($mailFiles as $f) {
        $dir = $f['dir'] ?? dirname($f['path']);
        $byDir[$dir][] = $f;
    }
    ?>
    <?php if (empty($mailFiles)): ?>
      <div class="alert alert-warning">Поштових логів не знайдено</div>
    <?php endif; ?>
    <form method="GET">
      <input type="hidden" name="sid" value="<?= $sid ?>">
      <div style="margin-bottom:14px;max-height:420px;overflow-y:auto">
        <?php foreach ($byDir as $dir => $dirFiles): ?>
        <div style="margin-bottom:12px">
          <div style="font-size:.72rem;font-weight:700;color:var(--blue-dark);background:var(--blue-ultra);padding:4px 8px;border-radius:4px;font-family:var(--font-mono);margin-bottom:4px">
            📁 <?= htmlspecialchars($dir) ?>
          </div>
          <?php foreach ($dirFiles as $f): ?>
          <label style="display:flex;align-items:center;gap:8px;padding:5px 8px;cursor:pointer;font-size:.83rem;border-radius:4px" onmouseover="this.style.background='var(--blue-ultra)'" onmouseout="this.style.background=''">
            <input type="checkbox" name="files[]" value="<?= htmlspecialchars($f['path']) ?>">
            <span style="font-family:var(--font-mono);flex:1"><?= htmlspecialchars($f['name']) ?></span>
            <span style="color:var(--gray-light);font-size:.73rem;white-space:nowrap"><?= $f['size'] > 0 ? number_format($f['size']/1024/1024,1).' MB' : '' ?></span>
          </label>
          <?php endforeach; ?>
        </div>
        <?php endforeach; ?>
      </div>
      <div style="display:flex;gap:10px;align-items:center;margin-bottom:14px;flex-wrap:wrap">
        <div>
          <label class="form-label" style="font-size:.76rem">Від дати</label>
          <input type="date" name="date_from" class="form-control" value="<?= htmlspecialchars($dateFrom) ?>">
        </div>
        <div>
          <label class="form-label" style="font-size:.76rem">До дати</label>
          <input type="date" name="date_to" class="form-control" value="<?= htmlspecialchars($dateTo) ?>">
        </div>
      </div>
      <div style="display:flex;gap:8px;align-items:center">
        <button type="submit" class="btn btn-primary">🔍 Завантажити</button>
        <button type="button" class="btn btn-outline btn-sm" onclick="
          document.querySelectorAll('[name=\'files[]\']').forEach(cb=>cb.checked=true)
        ">Всі</button>
        <button type="button" class="btn btn-outline btn-sm" onclick="
          document.querySelectorAll('[name=\'files[]\']').forEach(cb=>cb.checked=false)
        ">Жодного</button>
      </div>
    </form>
  </div>
</div>

<?php else: ?>
<!-- ── Фільтр-панель ── -->
<div class="filter-panel">
  <div class="filter-grid">
    <div>
      <label class="form-label" style="font-size:.76rem">📤 Від (from)</label>
      <input type="text" id="mfFrom" class="form-control" placeholder="user@example.com або @domain.com" oninput="applyFilter()">
    </div>
    <div>
      <label class="form-label" style="font-size:.76rem">📥 Кому (to)</label>
      <input type="text" id="mfTo" class="form-control" placeholder="user@example.com або @domain.com" oninput="applyFilter()">
    </div>
    <div>
      <label class="form-label" style="font-size:.76rem">📅 Від дати</label>
      <input type="date" id="mfDateFrom" class="form-control" value="<?= htmlspecialchars($dateFrom) ?>" onchange="applyFilter()">
    </div>
    <div>
      <label class="form-label" style="font-size:.76rem">📅 До дати</label>
      <input type="date" id="mfDateTo" class="form-control" value="<?= htmlspecialchars($dateTo) ?>" onchange="applyFilter()">
    </div>
    <div>
      <label class="form-label" style="font-size:.76rem">&nbsp;</label>
      <button class="btn btn-outline" onclick="clearFilter()" style="width:100%">✕ Скинути</button>
    </div>
  </div>

  <!-- Статус-чіпи -->
  <div class="mail-stats-row" style="margin-top:12px;margin-bottom:0">
    <div class="mail-stat-chip chip-all active" onclick="setStatus('')">
      Всі <span id="cntAll">0</span>
    </div>
    <div class="mail-stat-chip chip-sent" onclick="setStatus('sent')">
      ✓ Відправлено <span id="cntSent">0</span>
    </div>
    <div class="mail-stat-chip chip-bounced" onclick="setStatus('bounced')">
      ✗ Bounce <span id="cntBounced">0</span>
    </div>
    <div class="mail-stat-chip chip-deferred" onclick="setStatus('deferred')">
      ⏳ Deferred <span id="cntDeferred">0</span>
    </div>
    <div class="mail-stat-chip chip-expired" onclick="setStatus('expired')">
      💀 Expired <span id="cntExpired">0</span>
    </div>
    <div style="margin-left:auto;align-self:center;font-size:.78rem;color:var(--gray-mid)">
      Знайдено: <strong id="mfCount">0</strong>
    </div>
  </div>
</div>

<!-- ── Таблиця ── -->
<div class="table-wrap" id="tableWrap">
  <table class="mail-table" id="mailTable">
    <thead>
      <tr>
        <th onclick="sortBy('time')"    id="th-time"   >📅 Дата</th>
        <th onclick="sortBy('from')"    id="th-from"   >📤 Від</th>
        <th onclick="sortBy('to')"      id="th-to"     >📥 Кому</th>
        <th onclick="sortBy('subject')" id="th-subject">📝 Тема</th>
        <th onclick="sortBy('xmailer')" id="th-xmailer">📬 X-Mailer</th>
        <th onclick="sortBy('size')"    id="th-size"   >📦 Розмір</th>
        <th onclick="sortBy('status')"  id="th-status" >Статус</th>
        <th onclick="sortBy('delay')"   id="th-delay"  >⏱ Затримка</th>
      </tr>
    </thead>
    <tbody id="mailTbody"></tbody>
  </table>
</div>

<div class="table-footer">
  <span id="pageInfo"></span>
  <div style="display:flex;gap:8px">
    <button class="btn btn-outline btn-sm" id="btnPrev" onclick="changePage(-1)">← Назад</button>
    <button class="btn btn-outline btn-sm" id="btnNext" onclick="changePage(1)">Далі →</button>
  </div>
  <button class="btn btn-sm" onclick="exportCSV()" style="background:var(--green-ok);color:#fff;border:none">⬇ CSV</button>
</div>

<!-- ── Detail panel ── -->
<div class="detail-panel" id="detailPanel">
  <div class="detail-close" onclick="closeDetail()">✕</div>
  <h3 style="margin:0 0 16px;font-size:1rem;color:var(--blue-dark)">📧 Деталі повідомлення</h3>
  <div id="detailContent"></div>
</div>
<div id="detailOverlay" onclick="closeDetail()"
  style="display:none;position:fixed;inset:0;background:rgba(0,0,0,.2);z-index:999"></div>

<?php endif; ?>

</div></main>

<?php renderFooter(); ?>
</div>

<script>
const MAIL_DATA = <?= json_encode($msgs, JSON_UNESCAPED_UNICODE) ?>;
const PAGE_SIZE = 100;

let filtered  = [...MAIL_DATA];
let curPage   = 0;
let sortCol   = 'time';
let sortDir   = -1;
let curStatus = '';

// ── Утиліти ──
function fmtSize(b) {
    if (!b) return '—';
    if (b < 1024) return b + ' B';
    if (b < 1048576) return (b/1024).toFixed(1) + ' KB';
    return (b/1048576).toFixed(1) + ' MB';
}
function fmtDate(ts) {
    if (!ts) return '—';
    const d = new Date(ts * 1000);
    const opts  = {timeZone:'Europe/Kyiv', day:'2-digit', month:'2-digit', year:'numeric'};
    const tOpts = {timeZone:'Europe/Kyiv', hour:'2-digit', minute:'2-digit', second:'2-digit'};
    return d.toLocaleDateString('uk-UA', opts) + ' ' + d.toLocaleTimeString('uk-UA', tOpts);
}
function statusHtml(st) {
    const map = {sent:'✓ sent', bounced:'✗ bounce', deferred:'⏳ deferred', expired:'💀 expired'};
    return `<span class="ms-${st||'unknown'}">${map[st] || (st || '—')}</span>`;
}
function esc(s) { return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }

// ── Фільтрація ──
function applyFilter() {
    const from   = (document.getElementById('mfFrom').value    || '').trim().toLowerCase();
    const to     = (document.getElementById('mfTo').value      || '').trim().toLowerCase();
    const dFrom  = document.getElementById('mfDateFrom').value;
    const dTo    = document.getElementById('mfDateTo').value;
    const tsFrom = dFrom ? new Date(dFrom).getTime()/1000 : 0;
    const tsTo   = dTo   ? (new Date(dTo).getTime()/1000 + 86399) : Infinity;

    filtered = MAIL_DATA.filter(m => {
        if (curStatus && m.status !== curStatus) return false;
        // Строго: from шукається тільки в полі from
        if (from && !m.from.includes(from)) return false;
        // Строго: to шукається тільки в полі to
        if (to && !m.to.join('\n').includes(to)) return false;
        if (tsFrom && m.time && m.time < tsFrom) return false;
        if (tsTo !== Infinity && m.time && m.time > tsTo) return false;
        return true;
    });

    applySort();
    curPage = 0;
    updateCounts();
    render();
}

function setStatus(st) {
    curStatus = st;
    document.querySelectorAll('.mail-stat-chip').forEach(el => el.classList.remove('active'));
    const map = {'':'chip-all','sent':'chip-sent','bounced':'chip-bounced','deferred':'chip-deferred','expired':'chip-expired'};
    document.querySelector('.' + map[st])?.classList.add('active');
    applyFilter();
}

function clearFilter() {
    document.getElementById('mfFrom').value = '';
    document.getElementById('mfTo').value   = '';
    document.getElementById('mfDateFrom').value = '';
    document.getElementById('mfDateTo').value   = '';
    curStatus = '';
    document.querySelectorAll('.mail-stat-chip').forEach(el => el.classList.remove('active'));
    document.querySelector('.chip-all').classList.add('active');
    applyFilter();
}

// ── Сортування ──
function sortBy(col) {
    if (sortCol === col) sortDir *= -1;
    else { sortCol = col; sortDir = col === 'time' ? -1 : 1; }
    document.querySelectorAll('.mail-table th').forEach(th => {
        th.classList.remove('sort-asc','sort-desc');
    });
    const th = document.getElementById('th-' + col);
    if (th) th.classList.add(sortDir === 1 ? 'sort-asc' : 'sort-desc');
    applySort();
    curPage = 0;
    render();
}

function applySort() {
    filtered.sort((a, b) => {
        let va = a[sortCol] ?? 0;
        let vb = b[sortCol] ?? 0;
        if (Array.isArray(va)) va = va[0] || '';
        if (Array.isArray(vb)) vb = vb[0] || '';
        if (typeof va === 'string') va = va.toLowerCase();
        if (typeof vb === 'string') vb = vb.toLowerCase();
        return va < vb ? -sortDir : va > vb ? sortDir : 0;
    });
}

// ── Рендер ──
function render() {
    const start = curPage * PAGE_SIZE;
    const page  = filtered.slice(start, start + PAGE_SIZE);
    const tbody = document.getElementById('mailTbody');

    tbody.innerHTML = page.map((m, i) => `
      <tr onclick="showDetail(${start+i})" style="cursor:pointer">
        <td style="white-space:nowrap;font-size:.74rem">${fmtDate(m.time)}</td>
        <td title="${esc(m.from)}">${esc(m.from) || '—'}</td>
        <td title="${esc(m.to.join(', '))}">${m.to.slice(0,2).map(esc).join('<br>')}${m.to.length>2?`<span style="color:var(--gray-light)"> +${m.to.length-2}</span>`:''}</td>
        <td title="${esc(m.subject)}" style="max-width:180px">${m.subject ? esc(m.subject.substring(0,55)) + (m.subject.length>55?'…':'') : '<span style="color:var(--gray-light)">—</span>'}</td>
        <td style="max-width:140px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;font-size:.75rem;color:var(--gray-mid)" title="${esc(m.xmailer)}">${m.xmailer ? esc(m.xmailer.substring(0,30)) + (m.xmailer.length>30?'…':'') : '<span style="color:var(--gray-light)">—</span>'}</td>
        <td style="white-space:nowrap">${fmtSize(m.size)}</td>
        <td style="white-space:nowrap">${statusHtml(m.status)}</td>
        <td style="white-space:nowrap">${m.delay ? m.delay.toFixed(1)+'s' : '—'}</td>
      </tr>`).join('');

    // Пагінація
    const total = filtered.length;
    const pages = Math.ceil(total / PAGE_SIZE);
    document.getElementById('pageInfo').textContent =
        `Стор. ${curPage+1} / ${pages || 1}  (рядки ${start+1}–${Math.min(start+PAGE_SIZE,total)} з ${total.toLocaleString('uk-UA')})`;
    document.getElementById('btnPrev').disabled = curPage === 0;
    document.getElementById('btnNext').disabled = curPage >= pages - 1;
}

function changePage(d) {
    const pages = Math.ceil(filtered.length / PAGE_SIZE);
    curPage = Math.max(0, Math.min(pages-1, curPage + d));
    render();
    document.getElementById('tableWrap').scrollTop = 0;
}

// ── Лічильники статусів ──
function updateCounts() {
    const total   = MAIL_DATA.length;
    const cnt = {sent:0, bounced:0, deferred:0, expired:0};
    MAIL_DATA.forEach(m => { if (cnt[m.status] !== undefined) cnt[m.status]++; });
    document.getElementById('cntAll').textContent      = total.toLocaleString('uk-UA');
    document.getElementById('cntSent').textContent     = cnt.sent.toLocaleString('uk-UA');
    document.getElementById('cntBounced').textContent  = cnt.bounced.toLocaleString('uk-UA');
    document.getElementById('cntDeferred').textContent = cnt.deferred.toLocaleString('uk-UA');
    document.getElementById('cntExpired').textContent  = cnt.expired.toLocaleString('uk-UA');
    document.getElementById('mfCount').textContent     = filtered.length.toLocaleString('uk-UA');
}

// ── Деталі ──
function showDetail(idx) {
    const m = filtered[idx];
    if (!m) return;
    document.getElementById('detailContent').innerHTML = `
      <div class="detail-row"><span class="detail-lbl">QID</span><span class="detail-val" style="font-family:var(--font-mono)">${esc(m.qid)}</span></div>
      <div class="detail-row"><span class="detail-lbl">Час</span><span class="detail-val">${fmtDate(m.time)}</span></div>
      <div class="detail-row"><span class="detail-lbl">Від</span><span class="detail-val">${esc(m.from)||'—'}</span></div>
      <div class="detail-row"><span class="detail-lbl">Кому</span><span class="detail-val">${m.to.map(esc).join('<br>')||'—'}</span></div>
      <div class="detail-row"><span class="detail-lbl">Тема</span><span class="detail-val">${esc(m.subject)||'—'}</span></div>
      ${m.xmailer ? `<div class="detail-row"><span class="detail-lbl">X-Mailer</span><span class="detail-val" style="font-family:var(--font-mono);font-size:.8rem">${esc(m.xmailer)}</span></div>` : ''}
      <div class="detail-row"><span class="detail-lbl">Розмір</span><span class="detail-val">${fmtSize(m.size)}</span></div>
      <div class="detail-row"><span class="detail-lbl">Статус</span><span class="detail-val">${statusHtml(m.status)}</span></div>
      <div class="detail-row"><span class="detail-lbl">DSN</span><span class="detail-val">${esc(m.dsn)||'—'}</span></div>
      <div class="detail-row"><span class="detail-lbl">Затримка</span><span class="detail-val">${m.delay ? m.delay.toFixed(2)+'s' : '—'}</span></div>
      ${(m.status === 'deferred' || m.status === 'bounced') && m.reason ? `
      <div class="detail-row" style="align-items:flex-start">
        <span class="detail-lbl" style="padding-top:2px">Причина</span>
        <span class="detail-val" style="
          background:${m.status === 'bounced' ? 'var(--red-light)' : 'var(--orange-light)'};
          color:${m.status === 'bounced' ? 'var(--red-err)' : 'var(--orange-warn)'};
          border-left:3px solid ${m.status === 'bounced' ? 'var(--red-err)' : 'var(--orange-warn)'};
          padding:6px 10px; border-radius:0 4px 4px 0;
          font-family:var(--font-mono); font-size:.78rem; line-height:1.5;
          display:block; width:100%
        ">${esc(m.reason)}</span>
      </div>` : ''}
    `;
    document.getElementById('detailPanel').classList.add('open');
    document.getElementById('detailOverlay').style.display = '';
}
function closeDetail() {
    document.getElementById('detailPanel').classList.remove('open');
    document.getElementById('detailOverlay').style.display = 'none';
}

// ── CSV експорт ──
function exportCSV() {
    const rows = [['Дата','Від','Кому','Тема','Розмір (байт)','Статус','Затримка (с)','QID']];
    filtered.forEach(m => rows.push([
        fmtDate(m.time), m.from, m.to.join('; '), m.subject,
        m.size, m.status, m.delay||'', m.qid
    ]));
    const csv = rows.map(r => r.map(v => '"'+String(v||'').replace(/"/g,'""')+'"').join(',')).join('\n');
    const a = document.createElement('a');
    a.href = 'data:text/csv;charset=utf-8,\uFEFF' + encodeURIComponent(csv);
    a.download = 'mail_<?= date('Y-m-d') ?>_<?= $srv['name'] ?>.csv';
    a.click();
}

// ── Ініціалізація ──
document.addEventListener('DOMContentLoaded', () => {
    if (MAIL_DATA.length) {
        updateCounts();
        applyFilter();
        // Підсвічуємо сортування за замовч.
        const th = document.getElementById('th-time');
        if (th) th.classList.add('sort-desc');
    }
});
</script>
</body>
</html>
