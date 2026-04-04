<?php
require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/layout.php';
require_once __DIR__ . '/includes/ssh.php';
requireAuth();
$user = currentUser();
$db   = getDB();

$sid = (int)($_GET['sid'] ?? 0);
if (!$sid) { header('Location: servers.php'); exit; }

$st = $db->prepare("SELECT * FROM servers WHERE id=? AND user_id=?");
$st->execute([$sid, $user['id']]);
$server = $st->fetch();
if (!$server) { header('Location: servers.php'); exit; }

// Якщо прийшли з модалу з вже готовим кешем — SSH не робимо,
// JS передасть список файлів через sessionStorage на стороні браузера.
// Але PHP все одно підключається для аналізу — тут ми лише будуємо список.
// Оптимізація: якщо GET-параметр from_modal=1, список файлів буде
// заповнений JS-ом на клієнті з sessionStorage без повторного SSH.
$fromModal = (int)($_GET['from_modal'] ?? 0) === 1;

$conn    = $fromModal ? ['success' => true, 'conn' => null, '_modal_skip' => true] : sshConnect($server);
$files   = [];
$connErr = '';

if ($fromModal) {
    // Список файлів прийде з sessionStorage через JS після завантаження сторінки
    // SSH-з'єднання буде відкрито лише коли юзер натисне "Аналізувати"
    $db->prepare("UPDATE servers SET status='online',last_check=CURRENT_TIMESTAMP WHERE id=?")->execute([$sid]);
} elseif ($conn['success']) {
    // Mikrotik: читаємо файли через RouterOS CLI, не bash
    if (isMikrotik($server)) {
        $diskFiles = array_values(getMikrotikLogFiles($conn));
        // Завжди додаємо RAM-буфер першим (основне джерело логів)
        $info   = getMikrotikLogInfo($conn);
        $memRec = $info['total'] > 0 ? $info['total'] . ' записів' : 'RAM буфер';
        $files  = [['path'=>'__mikrotik_memory__', 'name'=>'RouterOS Memory Log ('.$memRec.')', 'size'=>1, 'mikrotik'=>true]];
        // Додаємо disk-файли якщо є (ненульові)
        foreach ($diskFiles as $df) {
            if ($df['size'] > 0) $files[] = $df;
        }
    } else {
        $files = array_values(getLogFiles($conn));
    }
    $db->prepare("UPDATE servers SET status='online',last_check=CURRENT_TIMESTAMP WHERE id=?")->execute([$sid]);
} else {
    $connErr = $conn['error'] ?? 'Не вдалось підключитись до сервера';
    $db->prepare("UPDATE servers SET status='offline',last_check=CURRENT_TIMESTAMP WHERE id=?")->execute([$sid]);
}

$sessions = $db->prepare("SELECT * FROM log_sessions WHERE server_id=? ORDER BY analyzed_at DESC LIMIT 8");
$sessions->execute([$sid]);
$sessions = $sessions->fetchAll();

function fmtSz(int $b): string {
    if ($b >= 1073741824) return round($b/1073741824,1).' GB';
    if ($b >= 1048576)    return round($b/1048576,1).' MB';
    if ($b >= 1024)       return round($b/1024,1).' KB';
    return $b.' B';
}
function logIcon(string $n): string {
    if (str_ends_with($n,'.gz'))      return '📦';
    if (str_contains($n,'mail') || str_contains($n,'maillog')) return '✉';
    if (str_contains($n,'mikrotik') || str_contains($n,'routeros')) return '🔶';
    if (str_contains($n,'named') || str_contains($n,'bind') || str_contains($n,'query')) return '🌐';
    if (str_contains($n,'syslog'))    return '🖥';
    if (str_contains($n,'error'))     return '🔴';
    if (str_contains($n,'access'))    return '📋';
    if (str_contains($n,'nginx'))     return '🟢';
    if (str_contains($n,'apache'))    return '🟠';
    return '📄';
}
?>
<!DOCTYPE html>
<html lang="uk">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Вибір логів — <?= htmlspecialchars($server['name']) ?> — LogPortal</title>
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
  <span class="bc-current"><?= htmlspecialchars($server['name']) ?></span>
</div></div>

<main class="page-content"><div class="container">

<div class="page-title-block">
  <div class="page-title-text">
    <h1>📂 Лог-файли сервера</h1>
    <div class="subtitle"><?= ($server['device_type'] ?? 'linux') === 'mikrotik' ? '🔶 MikroTik' : '🐧 Linux' ?> · <?= htmlspecialchars($server['name']) ?></div>
  </div>
  <a href="servers.php" class="btn btn-outline btn-sm">← Назад</a>
</div>

<?php if ($connErr): ?>
  <div class="alert alert-error">
    <span class="alert-icon">✕</span>
    <div><strong>Помилка підключення</strong><br><?= htmlspecialchars($connErr) ?></div>
  </div>
<?php else: ?>

<form method="GET" action="analyze.php" id="analyzeForm">
  <input type="hidden" name="sid" value="<?= $sid ?>">

<div class="grid-2" style="gap:20px;align-items:start">

  <!-- ── Ліва колонка: файли ── -->
  <div>
    <div class="card">
      <div class="card-header">
        <div class="card-header-title">
          📋 Знайдені лог-файли
          <span class="badge badge-info"><?= count($files) ?></span>
        </div>
        <div style="display:flex;gap:8px">
          <button type="button" onclick="selectAll()" class="btn btn-outline btn-sm">☑ Всі</button>
          <button type="button" onclick="selectNone()" class="btn btn-outline btn-sm">☐ Зняти</button>
          <a href="logs.php?sid=<?= $sid ?>" class="btn btn-outline btn-sm">🔄</a>
        </div>
      </div>

      <div class="card-body" style="padding:12px">
        <?php if (empty($files) && !$fromModal): ?>
          <div style="text-align:center;padding:32px;color:var(--gray-mid)">
            <div style="font-size:36px">🔍</div>
            <p>Файли не знайдено</p>
          </div>
        <?php else: ?>

          <!-- Пошук -->
          <div style="margin-bottom:10px;display:flex;gap:8px">
            <input type="text" id="fileFilter" class="form-control"
                   placeholder="🔍 Пошук по назві..."
                   oninput="filterFiles(this.value)"
                   style="font-size:.8rem;flex:1">
          </div>

          <!-- Список з групуванням по директоріях -->
          <div id="logList" style="max-height:520px;overflow-y:auto">
            <?php if (!$fromModal):
            // Групуємо по директорії
            $groups = [];
            foreach ($files as $f) {
                $dir = dirname($f['path']);
                $groups[$dir][] = $f;
            }
            foreach ($groups as $dir => $gfiles):
            ?>
            <div class="group-header" data-dir="<?= htmlspecialchars($dir) ?>">
              📁 <?= htmlspecialchars($dir) ?>
              <span style="font-weight:400;opacity:.7">(<?= count($gfiles) ?>)</span>
            </div>
            <?php foreach ($gfiles as $f):
              $fid = 'f_' . md5($f['path']); ?>
            <label class="log-item" for="<?= $fid ?>" data-name="<?= strtolower(htmlspecialchars($f['name'])) ?>" data-path="<?= strtolower(htmlspecialchars($dir)) ?>">
              <input type="checkbox" id="<?= $fid ?>" name="files[]"
                     value="<?= htmlspecialchars($f['path']) ?>"
                     onchange="onCheck(this)">
              <div class="log-item-icon"><?= logIcon(strtolower($f['name'])) ?></div>
              <div style="flex:1;min-width:0">
                <div class="log-item-name"><?= htmlspecialchars($f['name']) ?></div>
                <div class="log-item-path"><?= htmlspecialchars($dir) ?>/</div>
              </div>
              <div class="log-item-size"><?= fmtSz($f['size']) ?></div>
            </label>
            <?php endforeach; ?>
            <?php endforeach; ?>
            <?php endif; // !fromModal — JS заповнить якщо from_modal ?>
          </div>

          <!-- Sticky панель аналізу -->
          <div class="analyze-bar" <?= $fromModal ? 'style="display:none"' : '' ?>>
            <div class="sel-count">Вибрано: <strong id="selCount">0</strong> файлів</div>
            <button type="button" class="btn btn-outline btn-sm" id="mailBtn" disabled onclick="submitTo('mail_search.php')">
              ✉ Пошта
            </button>
            <button type="submit" class="btn btn-primary btn-sm" id="analyzeBtn" disabled>
              📊 Аналізувати
            </button>
          </div>

        <?php endif; ?>
      </div>
    </div>
  </div>

  <!-- ── Права колонка ── -->
  <div style="display:flex;flex-direction:column;gap:16px">

    <!-- Фільтр по датах -->
    <div class="card">
      <div class="card-header"><div class="card-header-title">📅 Фільтр по датах</div></div>
      <div class="card-body" style="padding:14px">
        <div style="display:grid;gap:10px">
          <div>
            <label style="font-size:.78rem;color:var(--gray-mid);display:block;margin-bottom:4px">Від дати</label>
            <input type="date" name="date_from" id="dateFrom" class="form-control" style="width:100%;font-size:.82rem">
          </div>
          <div>
            <label style="font-size:.78rem;color:var(--gray-mid);display:block;margin-bottom:4px">До дати</label>
            <input type="date" name="date_to" id="dateTo" class="form-control" style="width:100%;font-size:.82rem">
          </div>
          <div style="display:flex;gap:8px;flex-wrap:wrap">
            <button type="button" class="btn btn-outline btn-sm" onclick="setRange(0)">Сьогодні</button>
            <button type="button" class="btn btn-outline btn-sm" onclick="setRange(7)">7 днів</button>
            <button type="button" class="btn btn-outline btn-sm" onclick="setRange(30)">30 днів</button>
            <button type="button" class="btn btn-outline btn-sm" onclick="setRange(-1)">Весь час</button>
          </div>
        </div>
        <div style="margin-top:10px;padding:8px;background:var(--blue-ultra);border-radius:var(--radius);font-size:.75rem;color:var(--gray-mid)">
          💡 Фільтр застосовується під час аналізу — показуються лише рядки за вибраний період
        </div>
      </div>
    </div>

    <!-- Інформація про сервер -->
    <div class="card">
      <div class="card-header"><div class="card-header-title">🖥 Сервер</div></div>
      <div class="card-body" style="padding:14px">
        <table style="width:100%;font-size:.8rem;border-collapse:collapse">
          <?php foreach ([
            'Назва'       => $server['name'],
            'Хост'        => $server['host'],
            'Порт'        => $server['port'],
            'Логін'       => $server['ssh_user'],
            'Авторизація' => $server['auth_type']==='key'?'SSH Ключ':'Пароль',
          ] as $k => $v): ?>
          <tr>
            <td style="padding:4px 6px;color:var(--gray-mid);width:45%"><?= $k ?></td>
            <td style="padding:4px 6px;font-weight:500;font-family:var(--font-mono);font-size:.77rem"><?= htmlspecialchars((string)$v) ?></td>
          </tr>
          <?php endforeach; ?>
        </table>
        <div style="margin-top:10px">
          <a href="server_add.php?edit=<?= $sid ?>" class="btn btn-outline btn-sm" style="width:100%;text-align:center">✏ Редагувати</a>
        </div>
      </div>
    </div>

    <!-- Останні аналізи -->
    <?php if ($sessions): ?>
    <div class="card">
      <div class="card-header"><div class="card-header-title">📊 Останні аналізи</div></div>
      <div class="card-body" style="padding:10px">
        <?php foreach ($sessions as $sess): ?>
        <a href="analyze.php?sid=<?= $sid ?>&files[]=<?= urlencode($sess['log_file']) ?>"
           style="display:flex;align-items:center;gap:10px;padding:8px;border-radius:var(--radius);transition:var(--transition);text-decoration:none;color:inherit"
           onmouseover="this.style.background='var(--blue-ultra)'" onmouseout="this.style.background=''">
          <div style="font-size:16px"><?= logIcon(strtolower(basename($sess['log_file']))) ?></div>
          <div style="flex:1;min-width:0">
            <div style="font-size:.78rem;font-weight:600;font-family:var(--font-mono);white-space:nowrap;overflow:hidden;text-overflow:ellipsis">
              <?= htmlspecialchars(basename($sess['log_file'])) ?>
            </div>
            <div style="font-size:.7rem;color:var(--gray-mid)">
              <?= date('d.m.Y H:i', strtotime($sess['analyzed_at'])) ?> · <?= number_format($sess['total_requests']) ?> записів
            </div>
          </div>
          <span style="color:var(--blue-main)">›</span>
        </a>
        <?php endforeach; ?>
      </div>
    </div>
    <?php endif; ?>

  </div>
</div>
</form>

<?php endif; ?>
</div></main>

<!-- ── Progress Modal ── -->
<div class="modal-overlay" id="progressModal">
  <div class="modal-box">
    <div class="modal-title">
      <div class="modal-spinner"></div>
      Аналіз лог-файлів…
    </div>
    <div class="modal-files" id="modalFiles"></div>
    <ul class="modal-steps" id="modalSteps">
      <li class="modal-step pending" data-step="1"><span class="step-icon"></span> Підключення до сервера SSH</li>
      <li class="modal-step pending" data-step="2"><span class="step-icon"></span> Читання файлів</li>
      <li class="modal-step pending" data-step="3"><span class="step-icon"></span> Фільтрація по датах</li>
      <li class="modal-step pending" data-step="4"><span class="step-icon"></span> Парсинг та аналіз</li>
      <li class="modal-step pending" data-step="5"><span class="step-icon"></span> Побудова звіту</li>
    </ul>
    <div class="modal-bar-wrap"><div class="modal-bar-fill" id="modalBar"></div></div>
    <div style="font-size:.74rem;color:var(--gray-mid);margin-top:10px;text-align:center" id="modalHint">
      Зачекайте, великі файли можуть оброблятись кілька хвилин…
    </div>
  </div>
</div>

<?php renderFooter(); ?>

</div>
<script>
// ── Якщо прийшли з модалу — рендеримо список файлів з sessionStorage ────
(function() {
  const sid = <?= $sid ?>;
  const fromModal = <?= $fromModal ? 'true' : 'false' ?>;
  if (!fromModal) return;

  const raw = sessionStorage.getItem('logs_cache_' + sid);
  if (!raw) return; // Якщо кешу немає — список вже міг бути порожній, нічого не робимо

  let cache;
  try { cache = JSON.parse(raw); } catch(e) { return; }

  // Кеш дійсний 5 хвилин
  if (Date.now() - cache.ts > 300000) {
    sessionStorage.removeItem('logs_cache_' + sid);
    return;
  }

  const files = cache.files;
  if (!files || !files.length) return;

  const logList = document.getElementById('logList');
  if (!logList) return;

  // Очищаємо порожній стан якщо є
  logList.innerHTML = '';

  // Іконки
  function logIcon(name) {
    name = name.toLowerCase();
    if (name.endsWith('.gz'))                            return '📦';
    if (name.includes('mail') || name.includes('maillog')) return '✉';
    if (name.includes('mikrotik') || name.includes('routeros')) return '🔶';
    if (name.includes('named') || name.includes('bind') || name.includes('query')) return '🌐';
    if (name.includes('syslog'))                         return '🖥';
    if (name.includes('error'))                          return '🔴';
    if (name.includes('access'))                         return '📋';
    if (name.includes('nginx'))                          return '🟢';
    if (name.includes('apache'))                         return '🟠';
    return '📄';
  }
  function fmtSz(b) {
    if (b >= 1073741824) return (b/1073741824).toFixed(1) + ' GB';
    if (b >= 1048576)    return (b/1048576).toFixed(1)    + ' MB';
    if (b >= 1024)       return (b/1024).toFixed(1)       + ' KB';
    return b + ' B';
  }
  function esc(s) {
    return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  }

  // Групуємо по директорії
  const groups = {};
  files.forEach(f => {
    const dir = f.path === '__mikrotik_memory__'
      ? 'RouterOS'
      : f.path.replace(/\/[^/]+$/, '');
    if (!groups[dir]) groups[dir] = [];
    groups[dir].push(f);
  });

  let html = '';
  Object.entries(groups).forEach(([dir, gfiles]) => {
    html += `<div class="group-header" data-dir="${esc(dir)}">
      📁 ${esc(dir)} <span style="font-weight:400;opacity:.7">(${gfiles.length})</span>
    </div>`;
    gfiles.forEach(f => {
      const fid = 'f_' + Math.random().toString(36).slice(2);
      const nameL = f.name.toLowerCase();
      const dirL  = dir.toLowerCase();
      html += `<label class="log-item" for="${fid}"
          data-name="${esc(nameL)}" data-path="${esc(dirL)}">
        <input type="checkbox" id="${fid}" name="files[]"
               value="${esc(f.path)}" onchange="onCheck(this)">
        <div class="log-item-icon">${logIcon(f.name)}</div>
        <div style="flex:1;min-width:0">
          <div class="log-item-name">${esc(f.name)}</div>
          <div class="log-item-path">${esc(dir)}/</div>
        </div>
        <div class="log-item-size">${fmtSz(f.size)}</div>
      </label>`;
    });
  });

  logList.innerHTML = html;

  // Показуємо панель аналізу
  document.querySelectorAll('.analyze-bar').forEach(el => el.style.display = '');
  updateBar();
})();
function onCheck(cb) {
  const label = cb.closest('.log-item');
  label.classList.toggle('selected', cb.checked);
  updateBar();
}
function updateBar() {
  const n = document.querySelectorAll('#logList input[type=checkbox]:checked').length;
  document.getElementById('selCount').textContent = n;
  document.getElementById('analyzeBtn').disabled = n === 0;
  document.getElementById('mailBtn').disabled    = n === 0;
}
function submitTo(action) {
  const form = document.getElementById('analyzeForm');
  form.action = action;
  form.submit();
  form.action = 'analyze.php'; // скидаємо для наступного submit
}
function selectAll() {
  document.querySelectorAll('#logList input[type=checkbox]:not([style*="display:none"])').forEach(cb => {
    const row = cb.closest('.log-item');
    if (row && row.style.display !== 'none') { cb.checked = true; row.classList.add('selected'); }
  });
  updateBar();
}
function selectNone() {
  document.querySelectorAll('#logList input[type=checkbox]').forEach(cb => {
    cb.checked = false; cb.closest('.log-item').classList.remove('selected');
  });
  updateBar();
}
function filterFiles(q) {
  q = q.toLowerCase();
  document.querySelectorAll('#logList .group-header').forEach(h => {
    const dir = h.dataset.dir?.toLowerCase() || '';
    let vis = 0;
    let el = h.nextElementSibling;
    while (el && !el.classList.contains('group-header')) {
      const name = el.dataset.name || '';
      const path = el.dataset.path || '';
      const show = !q || name.includes(q) || path.includes(q);
      el.style.display = show ? '' : 'none';
      if (show) vis++;
      el = el.nextElementSibling;
    }
    h.style.display = vis || dir.includes(q) ? '' : 'none';
  });
}
function setRange(days) {
  const from = document.getElementById('dateFrom');
  const to   = document.getElementById('dateTo');
  const today = new Date();
  const fmt = d => d.toISOString().slice(0,10);
  to.value = fmt(today);
  if (days === 0)       { from.value = fmt(today); }
  else if (days === -1) { from.value = ''; to.value = ''; }
  else                  { const d = new Date(today); d.setDate(d.getDate()-days+1); from.value = fmt(d); }
}

// ── Progress Modal ──
const STEPS = [
  { el: null, label: 'Підключення до сервера SSH', ms: 800  },
  { el: null, label: 'Читання файлів',              ms: 2500 },
  { el: null, label: 'Фільтрація по датах',         ms: 800  },
  { el: null, label: 'Парсинг та аналіз',           ms: 4000 },
  { el: null, label: 'Побудова звіту',              ms: 600  },
];

document.addEventListener('DOMContentLoaded', () => {
  STEPS.forEach((s, i) => {
    s.el = document.querySelector(`[data-step="${i+1}"]`);
  });
});

document.getElementById('analyzeForm').addEventListener('submit', function(e) {
  e.preventDefault(); // Зупиняємо нативний submit

  const checked = [...document.querySelectorAll('#logList input[type=checkbox]:checked')];
  if (!checked.length) return;

  // Показуємо файли в модалці
  const names = checked.map(cb => cb.closest('.log-item').querySelector('.log-item-name').textContent.trim());
  document.getElementById('modalFiles').innerHTML = names.map(n => '📄 ' + n).join('<br>');

  // Відображаємо модальне вікно
  document.getElementById('progressModal').classList.add('active');

  // Будуємо URL вручну
  const form = document.getElementById('analyzeForm');
  const data = new FormData(form);
  const params = new URLSearchParams();
  for (const [k, v] of data.entries()) params.append(k, v);

  // Дату додаємо окремо якщо задано
  const df = document.getElementById('dateFrom')?.value;
  const dt = document.getElementById('dateTo')?.value;
  if (df) params.set('date_from', df);
  if (dt) params.set('date_to', dt);

  const url = 'analyze.php?' + params.toString();

  // Анімуємо кроки, потім переходимо
  animateSteps(0, url);
});

function setStep(idx, state) {
  const step = STEPS[idx]?.el;
  if (!step) return;
  step.className = 'modal-step ' + state;
}

function animateSteps(idx, url) {
  if (idx >= STEPS.length) {
    document.getElementById('modalHint').textContent = 'Формуємо звіт, зачекайте…';
    document.getElementById('modalBar').style.width = '98%';
    // Переходимо на сторінку аналізу лише після показу всіх кроків
    window.location.href = url;
    return;
  }

  for (let i = 0; i < idx; i++) setStep(i, 'done');
  setStep(idx, 'active');

  const pct = Math.round((idx / STEPS.length) * 95);
  document.getElementById('modalBar').style.width = pct + '%';

  setTimeout(() => animateSteps(idx + 1, url), STEPS[idx].ms);
}
</script>
</body>
</html>
