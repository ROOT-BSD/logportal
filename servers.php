<?php
/* ─────────────────────────────────────────────────────
   LogPortal — servers.php
   Список підключених SSH-серверів
   ───────────────────────────────────────────────────── */
require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/layout.php';
requireAuth();
sendSecurityHeaders();
$user = currentUser();
$db   = getDB();

// Видалення сервера
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['_action'] ?? '') === 'delete') {
    $sid = (int)($_POST['sid'] ?? 0);
    $db->prepare("DELETE FROM servers WHERE id=? AND user_id=?")->execute([$sid, $user['id']]);
    header('Location: servers.php?msg=' . urlencode('Сервер видалено') . '&mt=success');
    exit;
}

// Список серверів поточного користувача
$servers = $db->prepare("SELECT * FROM servers WHERE user_id=? ORDER BY created_at DESC");
$servers->execute([$user['id']]);
$servers = $servers->fetchAll();

$msg  = $_GET['msg'] ?? '';
$mt   = $_GET['mt']  ?? 'info';

function statusLabel(string $s): string {
    return match($s) { 'online'=>'Online', 'offline'=>'Offline', default=>'Невідомо' };
}
?>
<!DOCTYPE html>
<html lang="uk">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Сервери — LogPortal</title>
<link rel="stylesheet" href="css/style.css">
<script>
(function(){var t=localStorage.getItem('lp_theme');if(t)document.documentElement.setAttribute('data-theme',t);})();
</script>
</head>
<body>
<div class="page-wrap">

<?php renderGovStrip(); renderHeader($user); renderNav($user, 'servers'); ?>

  <!-- Breadcrumb -->
  <div class="breadcrumbs">
    <div class="container">
      <a href="servers.php">Головна</a>
      <span class="bc-sep">›</span>
      <span class="bc-current">Підключені сервери</span>
    </div>
  </div>

  <!-- Content -->
  <main class="page-content">
    <div class="container">

      <?php if ($msg): ?>
        <div class="alert alert-<?= htmlspecialchars($mt) ?>" style="margin-bottom:20px">
          <span class="alert-icon"><?= $mt==='success'?'✓':'ℹ' ?></span>
          <span><?= htmlspecialchars(urldecode($msg)) ?></span>
        </div>
      <?php endif; ?>

      <div class="page-title-block">
        <div class="page-title-text">
          <h1>&#x2316; Підключені сервери</h1>
          <div class="subtitle">Керування SSH-підключеннями до Linux-серверів та Mikrotik-маршрутизаторів</div>
        </div>
        <a href="server_add.php" class="btn btn-primary">&#x2b; Додати сервер</a>
      </div>

      <!-- Servers grid -->
      <div class="servers-grid">

        <?php if (empty($servers)): ?>
          <div style="grid-column:1/-1">
            <div class="card">
              <div class="empty-state">
                <div class="empty-icon">🖥️</div>
                <h3>Немає підключених серверів</h3>
                <p>Додайте перший сервер для аналізу логів</p>
                <a href="server_add.php" class="btn btn-primary" style="margin-top:20px">&#x2b; Додати перший сервер</a>
              </div>
            </div>
          </div>
        <?php else: ?>
          <?php foreach ($servers as $s): ?>
          <div class="server-card-wrap">
            <a href="logs.php?sid=<?= $s['id'] ?>" class="server-card">
              <div class="server-card-top">
                <div class="server-card-top-row">
                  <div class="server-icon-wrap">🖥️</div>
                  <div class="server-status status-<?= htmlspecialchars($s['status']) ?>">
                    <div class="status-dot"></div>
                    <?= statusLabel($s['status']) ?>
                  </div>
                </div>
                <div class="server-name"><?= ($s['device_type']??'linux')==='mikrotik' ? '🔶 ' : '🐧 ' ?><?= htmlspecialchars($s['name']) ?></div>
                <div class="server-host">
                  <?= htmlspecialchars($s['ssh_user']) ?>@<?= htmlspecialchars($s['host']) ?>:<?= (int)$s['port'] ?>
                </div>
              </div>
              <div class="server-card-body">
                <div class="server-meta">
                  <div class="server-meta-row">
                    <strong>Авторизація</strong>
                    <?= $s['auth_type']==='key' ? '🔐 SSH Ключ' : '🔑 Пароль' ?>
                  </div>
                  <div class="server-meta-row">
                    <strong>Додано</strong>
                    <?= date('d.m.Y', strtotime($s['created_at'])) ?>
                  </div>
                  <?php if ($s['last_check']): ?>
                  <div class="server-meta-row">
                    <strong>Перевірено</strong>
                    <?= date('d.m H:i', strtotime($s['last_check'])) ?>
                  </div>
                  <?php endif; ?>
                  <?php if ($s['description']): ?>
                  <div class="server-meta-row" style="grid-column:1/-1">
                    <strong>Опис</strong>
                    <?= htmlspecialchars(substr($s['description'],0,60)) ?>
                  </div>
                  <?php endif; ?>
                </div>
              </div>
            </a>
            <!-- Action footer -->
            <div class="server-card-footer" style="background:var(--white);border:1px solid var(--gray-border);border-top:none;border-radius:0 0 var(--radius-lg) var(--radius-lg);padding:10px 12px;display:flex;gap:8px">
              <a href="logs.php?sid=<?= $s['id'] ?>" class="btn btn-outline btn-sm" style="flex:1;justify-content:center">
                📂 Відкрити логи
              </a>
              <a href="server_add.php?edit=<?= $s['id'] ?>" class="btn btn-outline btn-sm" title="Редагувати">✏</a>
              <button class="btn btn-danger btn-sm"
                      onclick="confirmDelete(<?= $s['id'] ?>, '<?= htmlspecialchars(addslashes($s['name'])) ?>')"
                      title="Видалити">🗑</button>
            </div>
          </div>
          <?php endforeach; ?>
        <?php endif; ?>

        <!-- Add new card -->
        <a href="server_add.php" class="server-card-add">
          <div class="add-plus">+</div>
          <div class="add-label">Додати новий сервер</div>
          <div class="add-sublabel">Підключитись через SSH</div>
        </a>

      </div><!-- /.servers-grid -->
    </div><!-- /.container -->
  </main>

<!-- ++ Connection Modal ++ -->
<div class="conn-overlay" id="connModal">
  <div class="conn-box">
    <div class="conn-head">
      <div class="conn-icon" id="connIcon">🖥️</div>
      <div class="conn-head-info">
        <div class="conn-name" id="connName">&mdash;</div>
        <div class="conn-host" id="connHost">&mdash;</div>
      </div>
      <div class="conn-type-badge" id="connType">&mdash;</div>
    </div>
    <div class="conn-steps">
      <div class="conn-step active" id="cstep1">
        <div class="conn-step-dot"></div>
        <div class="conn-step-body">
          <span class="conn-step-label">Встановлення SSH-з’єднання</span>
          <span class="conn-step-spin"></span>
        </div>
      </div>
      <div class="conn-step" id="cstep2">
        <div class="conn-step-dot"></div>
        <div class="conn-step-body">
          <span class="conn-step-label">Автентифікація</span>
          <span class="conn-step-spin"></span>
        </div>
      </div>
      <div class="conn-step" id="cstep3">
        <div class="conn-step-dot"></div>
        <div class="conn-step-body">
          <span class="conn-step-label">Зчитування файлів журналів</span>
          <span class="conn-step-spin"></span>
        </div>
      </div>
    </div>
    <div class="conn-bar-wrap">
      <div class="conn-bar-fill" id="connBar"></div>
    </div>
    <div class="conn-bar-labels">
      <span id="connPct">0%</span>
      <span id="connMsg">Підключення…</span>
    </div>
  </div>
</div>


<?php renderFooter(); ?>

</div><!-- /.page-wrap -->

<form id="deleteForm" method="POST" style="display:none">
  <input type="hidden" name="_action" value="delete">
  <input type="hidden" name="sid" id="deleteSid">
</form>

<script>
(function(){var t=localStorage.getItem('lp_theme');if(t)document.documentElement.setAttribute('data-theme',t);})();

const SERVERS = <?php echo json_encode(array_map(fn($s) => [
  'id'          => (int)$s['id'],
  'name'        => $s['name'],
  'host'        => $s['host'],
  'port'        => (int)$s['port'],
  'ssh_user'    => $s['ssh_user'],
  'auth_type'   => $s['auth_type'],
  'device_type' => $s['device_type'] ?? 'linux',
  'status'      => $s['status'],
  'description' => $s['description'] ?? '',
  'created_at'  => $s['created_at'],
  'last_check'  => $s['last_check'] ?? '',
], $servers), JSON_UNESCAPED_UNICODE) ?>;

function setStep(n) {
  [1,2,3].forEach(i => {
    const el = document.getElementById('cstep'+i);
    el.classList.remove('active','done');
    if (i < n)  el.classList.add('done');
    if (i === n) el.classList.add('active');
  });
}
function setBar(pct, msg) {
  document.getElementById('connBar').style.width = pct + '%';
  document.getElementById('connPct').textContent  = Math.round(pct) + '%';
  document.getElementById('connMsg').textContent  = msg;
}
function allDone() {
  [1,2,3].forEach(i => {
    const el = document.getElementById('cstep'+i);
    el.classList.remove('active'); el.classList.add('done');
  });
}

let _sseSource = null;

function openConnModal(srv) {
  document.getElementById('connIcon').textContent = srv.device_type === 'mikrotik' ? '🔶' : '🖥️';
  document.getElementById('connName').textContent = srv.name;
  document.getElementById('connHost').textContent = srv.ssh_user + '@' + srv.host + ':' + srv.port;
  document.getElementById('connType').textContent =
    (srv.device_type === 'mikrotik' ? 'MikroTik 🔶' : 'Linux 🐧') +
    '  ·  ' +
    (srv.auth_type === 'key' ? 'SSH Ключ 🔐' : 'Пароль 🔑');

  setStep(1);
  setBar(0, 'Підключення…');
  document.getElementById('connModal').classList.add('open');
  document.body.style.overflow = 'hidden';

  // Закриваємо попередній SSE якщо є
  if (_sseSource) { _sseSource.close(); _sseSource = null; }

  const sseUrl  = 'api.php?action=list_logs&sid=' + srv.id;
  const destUrl = 'logs.php?sid=' + srv.id + '&from_modal=1';

  const es = new EventSource(sseUrl);
  _sseSource = es;

  es.addEventListener('progress', e => {
    const d = JSON.parse(e.data);
    setStep(d.step);
    setBar(d.pct, d.msg);
  });

  es.addEventListener('done', e => {
    es.close(); _sseSource = null;
    const d = JSON.parse(e.data);
    // Зберігаємо результат в sessionStorage щоб logs.php не робив повторний SSH
    sessionStorage.setItem('logs_cache_' + srv.id, JSON.stringify({
      ts: Date.now(),
      files: d.files
    }));
    allDone();
    setBar(100, 'Готово! Відкриваємо…');
    setTimeout(() => { window.location.href = destUrl; }, 350);
  });

  es.addEventListener('error', e => {
    try {
      const d = JSON.parse(e.data);
      setBar(0, '❌ ' + (d.msg || 'Помилка підключення'));
      document.getElementById('cstep1').classList.add('error');
    } catch(_) {}
    es.close(); _sseSource = null;
  });

  es.onerror = () => {
    // SSE закрилась без події error (наприклад php помилка)
    if (es.readyState === EventSource.CLOSED) {
      _sseSource = null;
    }
  };
}

// Клік на картку або кнопку "Відкрити логи"
document.querySelectorAll('.server-card-wrap').forEach(wrap => {
  const link = wrap.querySelector('a.server-card');
  if (!link) return;
  const sid = parseInt(new URL(link.href, location.href).searchParams.get('sid'));
  if (!sid) return;
  const srv = SERVERS.find(x => x.id === sid);
  if (!srv) return;

  link.addEventListener('click', e => { e.preventDefault(); openConnModal(srv); });

  const btnLogs = wrap.querySelector('a[href*="logs.php"]');
  if (btnLogs) btnLogs.addEventListener('click', e => { e.preventDefault(); openConnModal(srv); });
});

function confirmDelete(id, name) {
  if (confirm('Видалити сервер «' + name + '»?\nВсі сесії аналізу також будуть видалені.')) {
    document.getElementById('deleteSid').value = id;
    document.getElementById('deleteForm').submit();
  }
}

// Перевірка статусу
document.querySelectorAll('.server-card-wrap').forEach(wrap => {
  const link = wrap.querySelector('a.server-card');
  if (!link) return;
  const sid = new URL(link.href, location.href).searchParams.get('sid');
  if (!sid) return;
  fetch('api.php?action=check_status&sid=' + sid)
    .then(r => r.json())
    .then(data => {
      const dot = wrap.querySelector('.server-status');
      if (!dot) return;
      dot.className = 'server-status status-' + data.status;
      dot.innerHTML = '<div class="status-dot"></div> ' +
        (data.status === 'online' ? 'Online' : data.status === 'offline' ? 'Offline' : 'Невідомо');
    })
    .catch(() => {});
});
</script>
</body>
</html>
