<?php
require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/ssh.php';
require_once __DIR__ . '/includes/layout.php';
requireAuth();
$user = currentUser();
if ($user['role'] !== 'admin') { header('Location: servers.php'); exit; }

$db  = getDB();
$msg = '';
$err = '';

// ── Дії ──
$action = $_POST['action'] ?? '';

if ($action === 'save_settings') {
    $smtpHost = trim($_POST['smtp_host'] ?? '');
    $smtpPort = trim($_POST['smtp_port'] ?? '25');
    $smtpUser = trim($_POST['smtp_user'] ?? '');
    $smtpPass = trim($_POST['smtp_pass'] ?? '');
    $smtpFrom = trim($_POST['smtp_from'] ?? '');
    $alertTo  = trim($_POST['alert_to']  ?? '');
    $orgName  = trim($_POST['org_name']  ?? '');
    $stmt = $db->prepare("INSERT OR REPLACE INTO settings(key,value) VALUES(?,?)");
    $stmt->execute(['smtp_host', $smtpHost]);
    $stmt->execute(['smtp_port', $smtpPort]);
    $stmt->execute(['smtp_user', $smtpUser]);
    if ($smtpPass !== '') $stmt->execute(['smtp_pass', encrypt($smtpPass)]);
    $stmt->execute(['smtp_from', $smtpFrom]);
    $stmt->execute(['alert_to',  $alertTo]);
    if ($orgName !== '') $stmt->execute(['org_name', $orgName]);
    $msg = 'Налаштування збережено';
}
function _getSetting(PDO $db, string $key): string {
    $r = $db->query("SELECT value FROM settings WHERE key='$key'");
    return $r ? ($r->fetchColumn() ?: '') : '';
}
$smtpHost = _getSetting($db, 'smtp_host');
$smtpPort = _getSetting($db, 'smtp_port') ?: '25';
$smtpUser = _getSetting($db, 'smtp_user');
$smtpPassEnc = _getSetting($db, 'smtp_pass');
$smtpFrom = _getSetting($db, 'smtp_from');
$alertTo  = _getSetting($db, 'alert_to');
$orgName  = _getSetting($db, 'org_name') ?: 'УІТ НКРЕКП';

if ($action === 'delete_user') {
    $uid = (int)($_POST['uid'] ?? 0);
    if ($uid === $user['id']) { $err = 'Не можна видалити свій власний акаунт'; }
    elseif ($uid < 1)         { $err = 'Невірний ID'; }
    else {
        $db->prepare("DELETE FROM users WHERE id=?")->execute([$uid]);
        $msg = 'Користувача видалено';
    }
}
elseif ($action === 'change_role') {
    $uid  = (int)($_POST['uid']  ?? 0);
    $role = $_POST['role'] ?? 'user';
    if (!in_array($role, ['admin','user'], true)) { $err = 'Невірна роль'; }
    elseif ($uid === $user['id'])                 { $err = 'Не можна змінити свою роль'; }
    else {
        $db->prepare("UPDATE users SET role=? WHERE id=?")->execute([$role, $uid]);
        $msg = 'Роль змінено';
    }
}
elseif ($action === 'reset_password') {
    $uid  = (int)($_POST['uid'] ?? 0);
    $newp = trim($_POST['new_password'] ?? '');
    if (strlen($newp) < 6) { $err = 'Пароль — мінімум 6 символів'; }
    else {
        $db->prepare("UPDATE users SET password=? WHERE id=?")->execute([password_hash($newp, PASSWORD_DEFAULT), $uid]);
        $msg = 'Пароль скинуто';
    }
}
elseif ($action === 'create_user') {
    $err = doRegister(
        trim($_POST['username']   ?? ''),
        trim($_POST['password']   ?? ''),
        trim($_POST['password2']  ?? ''),
        trim($_POST['email']      ?? '')
    );
    if (!$err) {
        // Якщо треба — виставляємо роль admin
        if (($_POST['role'] ?? 'user') === 'admin') {
            $newId = $db->lastInsertId();
            $db->prepare("UPDATE users SET role='admin' WHERE id=?")->execute([$newId]);
        }
        $msg = "Користувача «{$_POST['username']}» створено";
    }
} elseif ($action === 'delete_server') {
    $sid = (int)($_POST['sid'] ?? 0);
    $db->prepare("DELETE FROM servers WHERE id=?")->execute([$sid]);
    $msg = 'Сервер видалено';
} elseif ($action === 'clear_sessions') {
    $sid = (int)($_POST['sid'] ?? 0);
    if ($sid) $db->prepare("DELETE FROM log_sessions WHERE server_id=?")->execute([$sid]);
    else      $db->exec("DELETE FROM log_sessions");
    $msg = 'Сесії аналізу очищено';
} elseif ($action === 'detect_gateway') {
    // AJAX: визначити gateway для сервера
    header('Content-Type: application/json');
    $sid = (int)($_POST['sid'] ?? 0);
    if (!$sid) { echo json_encode(['ok'=>false,'error'=>'Не вказано сервер']); exit; }
    $srv = $db->prepare("SELECT * FROM servers WHERE id=?")->execute([$sid]) ?
           $db->prepare("SELECT * FROM servers WHERE id=?")->execute([$sid]) : null;
    $srvRow = $db->prepare("SELECT * FROM servers WHERE id=?");
    $srvRow->execute([$sid]);
    $srvRow = $srvRow->fetch(PDO::FETCH_ASSOC);
    if (!$srvRow) { echo json_encode(['ok'=>false,'error'=>'Сервер не знайдено']); exit; }
    if (($srvRow['device_type'] ?? 'linux') !== 'linux') {
        echo json_encode(['ok'=>false,'error'=>'Gateway визначається тільки для Linux серверів']); exit;
    }
    $conn = sshConnect($srvRow);
    if (!$conn['success']) {
        echo json_encode(['ok'=>false,'error'=>'SSH: '.($conn['error'] ?? 'помилка підключення')]); exit;
    }
    $gw = detectGateway($conn);
    if ($gw === '') {
        echo json_encode(['ok'=>false,'error'=>'Не вдалось визначити gateway (команди ip route / route -n не повернули результат)']); exit;
    }
    $db->prepare("UPDATE servers SET gateway=? WHERE id=?")->execute([$gw, $sid]);
    echo json_encode(['ok'=>true,'gateway'=>$gw,'msg'=>"Gateway визначено: {$gw}"]); exit;
} elseif ($action === 'save_gateway') {
    // Зберегти gateway вручну
    header('Content-Type: application/json');
    $sid = (int)($_POST['sid'] ?? 0);
    $gw  = trim($_POST['gateway'] ?? '');
    if (!$sid) { echo json_encode(['ok'=>false,'error'=>'Не вказано сервер']); exit; }
    if ($gw !== '' && !preg_match('/^(\d{1,3}\.){3}\d{1,3}$/', $gw)) {
        echo json_encode(['ok'=>false,'error'=>'Невірний формат IP']); exit;
    }
    $db->prepare("UPDATE servers SET gateway=? WHERE id=?")->execute([$gw, $sid]);
    echo json_encode(['ok'=>true,'gateway'=>$gw,'msg'=>$gw ? "Gateway збережено: {$gw}" : 'Gateway очищено']); exit;
}

// ── Дані ──
$users   = $db->query("SELECT u.*,
    (SELECT COUNT(*) FROM servers s WHERE s.user_id=u.id) AS srv_count,
    (SELECT COUNT(*) FROM log_sessions ls JOIN servers s ON ls.server_id=s.id WHERE s.user_id=u.id) AS sess_count
    FROM users u ORDER BY u.created_at DESC")->fetchAll();

$servers = $db->query("SELECT s.*, u.username,
    (SELECT COUNT(*) FROM log_sessions ls WHERE ls.server_id=s.id) AS sess_count
    FROM servers s JOIN users u ON s.user_id=u.id ORDER BY s.created_at DESC")->fetchAll();

$stats = $db->query("
    SELECT
      (SELECT COUNT(*) FROM users) AS total_users,
      (SELECT COUNT(*) FROM users WHERE role='admin') AS admin_count,
      (SELECT COUNT(*) FROM servers) AS total_servers,
      (SELECT COUNT(*) FROM log_sessions) AS total_sessions,
      (SELECT COUNT(*) FROM servers WHERE status='online') AS online_servers,
      (SELECT MAX(analyzed_at) FROM log_sessions) AS last_analysis
")->fetch();
?>
<!DOCTYPE html>
<html lang="uk">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Адмінка — LogPortal</title>
<link rel="stylesheet" href="css/style.css">
<script>
(function(){var t=localStorage.getItem('lp_theme');if(t)document.documentElement.setAttribute('data-theme',t);})();
</script>
</head>
<body>
<div class="page-wrap">

<?php renderGovStrip(); renderHeader($user); renderNav($user, 'admin'); ?>
<div class="breadcrumbs"><div class="container">
  <a href="servers.php">Головна</a><span class="bc-sep">›</span>
  <span class="bc-current">Адміністрування</span>
</div></div>

<main class="page-content"><div class="container">

<div class="page-title-block">
  <div class="page-title-text">
    <h1>⚙ Панель адміністратора</h1>
    <div class="subtitle">Управління користувачами, серверами та сесіями</div>
  </div>
</div>

<?php if ($msg): ?>
<div class="alert alert-success" style="margin-bottom:16px">
  <span class="alert-icon">✓</span> <?= htmlspecialchars($msg) ?>
</div>
<?php endif; ?>
<?php if ($err): ?>
<div class="alert alert-error" style="margin-bottom:16px">
  <span class="alert-icon">✕</span> <?= htmlspecialchars($err) ?>
</div>
<?php endif; ?>

<!-- Статистика -->
<div class="stat-mini">
  <div class="stat-mini-card">
    <div class="stat-mini-val"><?= $stats['total_users'] ?></div>
    <div class="stat-mini-lbl">👤 Користувачів</div>
  </div>
  <div class="stat-mini-card" style="border-top-color:var(--orange-warn)">
    <div class="stat-mini-val"><?= $stats['admin_count'] ?></div>
    <div class="stat-mini-lbl">🔑 Адміністраторів</div>
  </div>
  <div class="stat-mini-card" style="border-top-color:var(--green-ok)">
    <div class="stat-mini-val"><?= $stats['total_servers'] ?></div>
    <div class="stat-mini-lbl">🖥 Серверів всього</div>
  </div>
  <div class="stat-mini-card" style="border-top-color:var(--green-ok)">
    <div class="stat-mini-val"><?= $stats['online_servers'] ?></div>
    <div class="stat-mini-lbl"><span class="online-dot"></span>Online зараз</div>
  </div>
  <div class="stat-mini-card" style="border-top-color:var(--orange-warn)">
    <div class="stat-mini-val"><?= $stats['total_sessions'] ?></div>
    <div class="stat-mini-lbl">📊 Аналізів всього</div>
  </div>
  <div class="stat-mini-card" style="border-top-color:var(--gray-mid)">
    <div class="stat-mini-val" style="font-size:1rem">
      <?= $stats['last_analysis'] ? date('d.m H:i', strtotime($stats['last_analysis'])) : '—' ?>
    </div>
    <div class="stat-mini-lbl">🕐 Останній аналіз</div>
  </div>
</div>

<!-- Вкладки -->
<div class="admin-tabs">
  <div class="admin-tab active" onclick="switchTab('users')">👤 Користувачі (<?= count($users) ?>)</div>
  <div class="admin-tab" onclick="switchTab('servers')">🖥 Сервери (<?= count($servers) ?>)</div>
  <div class="admin-tab" onclick="switchTab('create')">➕ Новий користувач</div>
</div>

<!-- TAB: Користувачі -->
<div class="tab-panel active" id="tab-users">
  <div class="card">
    <div class="card-header">
      <div class="card-header-title">👤 Список користувачів</div>
    </div>
    <div class="card-body" style="padding:0;overflow-x:auto">
      <table class="users-table">
        <thead>
          <tr>
            <th>#</th><th>Логін</th><th>Email</th><th>Роль</th>
            <th>Серверів</th><th>Аналізів</th>
            <th>Реєстрація</th><th>Останній вхід</th><th>Дії</th>
          </tr>
        </thead>
        <tbody>
        <?php foreach ($users as $u): ?>
        <tr>
          <td style="color:var(--gray-mid)"><?= $u['id'] ?></td>
          <td>
            <strong><?= htmlspecialchars($u['username']) ?></strong>
            <?php if ($u['id'] == $user['id']): ?>
              <span style="font-size:.7rem;color:var(--gray-light)">(ви)</span>
            <?php endif; ?>
          </td>
          <td style="color:var(--gray-mid)"><?= htmlspecialchars($u['email'] ?? '—') ?></td>
          <td><span class="role-badge role-<?= $u['role'] ?>"><?= $u['role'] ?></span></td>
          <td class="num"><?= $u['srv_count'] ?></td>
          <td class="num"><?= $u['sess_count'] ?></td>
          <td style="font-size:.76rem;color:var(--gray-mid)"><?= $u['created_at'] ? date('d.m.Y', strtotime($u['created_at'])) : '—' ?></td>
          <td style="font-size:.76rem;color:var(--gray-mid)"><?= $u['last_login'] ? date('d.m.Y H:i', strtotime($u['last_login'])) : 'Ніколи' ?></td>
          <td>
            <?php if ($u['id'] != $user['id']): ?>
            <div class="action-btns">
              <button class="btn-info"    onclick="openRoleModal(<?= $u['id'] ?>, '<?= $u['username'] ?>', '<?= $u['role'] ?>')">✏ Роль</button>
              <button class="btn-warning" onclick="openPassModal(<?= $u['id'] ?>, '<?= $u['username'] ?>')">🔑 Пароль</button>
              <button class="btn-danger"  onclick="openDelModal(<?= $u['id'] ?>, '<?= htmlspecialchars($u['username']) ?>', <?= $u['srv_count'] ?>)">✕ Видалити</button>
            </div>
            <?php else: ?>
              <span style="font-size:.75rem;color:var(--gray-light)">—</span>
            <?php endif; ?>
          </td>
        </tr>
        <?php endforeach; ?>
        </tbody>
      </table>
    </div>
  </div>
</div>

<!-- TAB: Сервери -->
<div class="tab-panel" id="tab-servers">
  <div class="card">
    <div class="card-header">
      <div class="card-header-title">🖥 Усі сервери</div>
      <form method="POST" onsubmit="return confirm('Очистити ВСІ сесії аналізу?')">
        <input type="hidden" name="action" value="clear_sessions">
        <button type="submit" class="btn btn-outline btn-sm" style="color:var(--orange-warn)">🗑 Очистити всі сесії</button>
      </form>
    </div>
    <div class="card-body" style="padding:0;overflow-x:auto">
      <table class="servers-table">
        <thead>
          <tr>
            <th>#</th><th>Назва</th><th>Хост</th><th>Порт</th>
            <th>Логін</th><th>Auth</th><th>Gateway</th><th>Власник</th>
            <th>Статус</th><th>Аналізів</th><th>Додано</th><th>Дії</th>
          </tr>
        </thead>
        <tbody>
        <?php foreach ($servers as $srv): ?>
        <tr>
          <td style="color:var(--gray-mid)"><?= $srv['id'] ?></td>
          <td><strong><?= htmlspecialchars($srv['name']) ?></strong></td>
          <td class="mono"><?= htmlspecialchars($srv['host']) ?></td>
          <td class="num"><?= $srv['port'] ?></td>
          <td class="mono"><?= htmlspecialchars($srv['ssh_user']) ?></td>
          <td>
            <span class="badge <?= $srv['auth_type']==='key' ? 'badge-info' : 'badge-3xx' ?>">
              <?= $srv['auth_type']==='key' ? '🔑 key' : '🔒 pass' ?>
            </span>
          </td>
          <td id="gw-cell-<?= $srv['id'] ?>" style="min-width:130px">
            <?php if (($srv['device_type']??'linux') === 'linux'): ?>
            <div style="display:flex;align-items:center;gap:4px;flex-wrap:wrap">
              <span id="gw-val-<?= $srv['id'] ?>" class="mono" style="font-size:.78rem;color:var(--blue-dark)">
                <?= htmlspecialchars($srv['gateway'] ?? '') ?: '<span style="color:var(--gray-mid)">—</span>' ?>
              </span>
              <button onclick="detectGw(<?= $srv['id'] ?>)"
                id="gw-btn-<?= $srv['id'] ?>"
                title="Визначити gateway через SSH"
                style="background:var(--blue-ultra);color:var(--blue-dark);border:1px solid var(--blue-light);border-radius:4px;padding:1px 6px;font-size:.7rem;cursor:pointer;white-space:nowrap">
                ⟳ SSH
              </button>
            </div>
            <?php else: ?>
            <span style="color:var(--gray-mid);font-size:.75rem">MikroTik</span>
            <?php endif; ?>
          </td>
          <td><?= htmlspecialchars($srv['username']) ?></td>
          <td>
            <span class="server-status status-<?= $srv['status'] ?>">
              <div class="status-dot"></div><?= $srv['status'] ?>
            </span>
          </td>
          <td class="num"><?= $srv['sess_count'] ?></td>
          <td style="font-size:.76rem;color:var(--gray-mid)"><?= $srv['created_at'] ? date('d.m.Y', strtotime($srv['created_at'])) : '—' ?></td>
          <td>
            <div class="action-btns">
              <?php if ($srv['sess_count'] > 0): ?>
              <form method="POST" style="display:inline" onsubmit="return confirm('Очистити сесії сервера?')">
                <input type="hidden" name="action" value="clear_sessions">
                <input type="hidden" name="sid" value="<?= $srv['id'] ?>">
                <button type="submit" class="btn-warning">🗑 Сесії</button>
              </form>
              <?php endif; ?>
              <button class="btn-danger" onclick="openDelSrvModal(<?= $srv['id'] ?>, '<?= htmlspecialchars($srv['name']) ?>')">✕ Видалити</button>
            </div>
          </td>
        </tr>
        <?php endforeach; ?>
        </tbody>
      </table>
    </div>
  </div>
</div>

<!-- TAB: Новий користувач -->
<div class="tab-panel" id="tab-create">
  <div class="card" style="max-width:560px">
    <div class="card-header"><div class="card-header-title">➕ Створити користувача</div></div>
    <div class="card-body" style="padding:20px">
      <form method="POST">
        <input type="hidden" name="action" value="create_user">
        <div class="create-form">
          <div>
            <label class="form-label">Логін *</label>
            <input type="text" name="username" class="form-control" required minlength="3" placeholder="login123">
          </div>
          <div>
            <label class="form-label">Email</label>
            <input type="email" name="email" class="form-control" placeholder="user@example.com">
          </div>
          <div>
            <label class="form-label">Пароль *</label>
            <input type="password" name="password" class="form-control" required minlength="6">
          </div>
          <div>
            <label class="form-label">Пароль ще раз *</label>
            <input type="password" name="password2" class="form-control" required minlength="6">
          </div>
          <div>
            <label class="form-label">Роль</label>
            <select name="role" class="form-control">
              <option value="user">user — звичайний</option>
              <option value="admin">admin — адміністратор</option>
            </select>
          </div>
          <div class="full" style="margin-top:8px">
            <button type="submit" class="btn btn-primary">➕ Створити</button>
          </div>
        </div>
      </form>
    </div>
  </div>
</div>

  <!-- ── Email алерти ── -->
  <div class="section-header" style="margin-top:32px">
    <h2 class="section-title">📧 Email алерти та налаштування</h2>
  </div>
  <div class="card">
    <form method="POST">
      <input type="hidden" name="action" value="save_settings">
      <div class="card-body" style="padding:16px 20px">

        <!-- Рядок 1: SMTP -->
        <div style="display:grid;grid-template-columns:2fr 1fr 1fr 1fr;gap:10px;margin-bottom:10px;align-items:end">
          <div>
            <label class="form-label" style="font-size:.75rem;margin-bottom:3px">SMTP сервер</label>
            <input type="text" name="smtp_host" class="form-control" style="font-size:.82rem"
              value="<?= htmlspecialchars($smtpHost) ?>" placeholder="mail.example.com">
          </div>
          <div>
            <label class="form-label" style="font-size:.75rem;margin-bottom:3px">Порт
              <span style="font-weight:400;color:var(--gray-mid)">25 · 465 · 587</span>
            </label>
            <input type="text" name="smtp_port" class="form-control" style="font-size:.82rem"
              value="<?= htmlspecialchars($smtpPort) ?>" placeholder="25">
          </div>
          <div>
            <label class="form-label" style="font-size:.75rem;margin-bottom:3px">Логін</label>
            <input type="text" name="smtp_user" class="form-control" style="font-size:.82rem"
              value="<?= htmlspecialchars($smtpUser) ?>" placeholder="user@example.com">
          </div>
          <div>
            <label class="form-label" style="font-size:.75rem;margin-bottom:3px">Пароль</label>
            <input type="password" name="smtp_pass" class="form-control" style="font-size:.82rem"
              value="" placeholder="<?= $smtpPassEnc ? '••••••••' : 'пароль' ?>">
          </div>
        </div>

        <!-- Рядок 2: From / To / Org -->
        <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px;margin-bottom:14px;align-items:end">
          <div>
            <label class="form-label" style="font-size:.75rem;margin-bottom:3px">Відправник (From)</label>
            <input type="email" name="smtp_from" class="form-control" style="font-size:.82rem"
              value="<?= htmlspecialchars($smtpFrom) ?>" placeholder="logportal@example.com">
          </div>
          <div>
            <label class="form-label" style="font-size:.75rem;margin-bottom:3px">Отримувач алертів (To)</label>
            <input type="email" name="alert_to" class="form-control" style="font-size:.82rem"
              value="<?= htmlspecialchars($alertTo) ?>" placeholder="admin@example.com">
          </div>
          <div>
            <label class="form-label" style="font-size:.75rem;margin-bottom:3px">Назва організації
              <span style="font-weight:400;color:var(--gray-mid)">(шапка порталу)</span>
            </label>
            <input type="text" name="org_name" class="form-control" style="font-size:.82rem"
              value="<?= htmlspecialchars($orgName) ?>" placeholder="УІТ НКРЕКП">
          </div>
        </div>

        <!-- Кнопка + статус -->
        <div style="display:flex;align-items:center;gap:12px;padding-top:2px;border-top:1px solid var(--gray-border)">
          <button type="submit" class="btn-primary" style="padding:7px 20px;font-size:.82rem">💾 Зберегти</button>
          <?php if ($smtpHost && $alertTo): ?>
          <span style="font-size:.78rem;color:var(--green-ok)">✅ Email налаштовано → <?= htmlspecialchars($alertTo) ?></span>
          <?php else: ?>
          <span style="font-size:.78rem;color:var(--gray-mid)">⚠ Не налаштовано</span>
          <?php endif; ?>
        </div>

      </div>
    </form>
  </div>
</div></main>

<!-- ── Modal: Видалення користувача ── -->
<div class="mini-modal" id="delModal">
  <div class="mini-modal-box">
    <div class="mini-modal-title">🗑 Видалити користувача</div>
    <p style="font-size:.86rem;color:var(--gray-mid);margin:0 0 8px">
      Видалити <strong id="delName"></strong>?<br>
      <span id="delWarn" style="color:var(--red-err);font-size:.8rem"></span>
    </p>
    <p style="font-size:.78rem;color:var(--gray-light)">Всі його сервери та сесії аналізу також будуть видалені.</p>
    <form method="POST">
      <input type="hidden" name="action" value="delete_user">
      <input type="hidden" name="uid" id="delUid">
      <div class="mini-modal-footer">
        <button type="button" class="btn btn-outline btn-sm" onclick="closeModal('delModal')">Скасувати</button>
        <button type="submit" class="btn btn-sm" style="background:var(--red-err);color:#fff;border:none">✕ Видалити</button>
      </div>
    </form>
  </div>
</div>

<!-- ── Modal: Зміна ролі ── -->
<div class="mini-modal" id="roleModal">
  <div class="mini-modal-box">
    <div class="mini-modal-title">✏ Змінити роль</div>
    <p style="font-size:.86rem;color:var(--gray-mid);margin:0 0 14px">
      Користувач: <strong id="roleName"></strong>
    </p>
    <form method="POST">
      <input type="hidden" name="action" value="change_role">
      <input type="hidden" name="uid" id="roleUid">
      <div style="margin-bottom:16px">
        <label class="form-label">Нова роль</label>
        <select name="role" id="roleSelect" class="form-control">
          <option value="user">user — звичайний</option>
          <option value="admin">admin — адміністратор</option>
        </select>
      </div>
      <div class="mini-modal-footer">
        <button type="button" class="btn btn-outline btn-sm" onclick="closeModal('roleModal')">Скасувати</button>
        <button type="submit" class="btn btn-primary btn-sm">✓ Зберегти</button>
      </div>
    </form>
  </div>
</div>

<!-- ── Modal: Скидання пароля ── -->
<div class="mini-modal" id="passModal">
  <div class="mini-modal-box">
    <div class="mini-modal-title">🔑 Скинути пароль</div>
    <p style="font-size:.86rem;color:var(--gray-mid);margin:0 0 14px">
      Користувач: <strong id="passName"></strong>
    </p>
    <form method="POST">
      <input type="hidden" name="action" value="reset_password">
      <input type="hidden" name="uid" id="passUid">
      <div style="margin-bottom:16px">
        <label class="form-label">Новий пароль</label>
        <input type="password" name="new_password" id="newPassInput" class="form-control" minlength="6" required placeholder="мінімум 6 символів">
      </div>
      <div class="mini-modal-footer">
        <button type="button" class="btn btn-outline btn-sm" onclick="closeModal('passModal')">Скасувати</button>
        <button type="submit" class="btn btn-primary btn-sm">🔑 Скинути</button>
      </div>
    </form>
  </div>
</div>

<!-- ── Modal: Видалення сервера ── -->
<div class="mini-modal" id="delSrvModal">
  <div class="mini-modal-box">
    <div class="mini-modal-title">🗑 Видалити сервер</div>
    <p style="font-size:.86rem;color:var(--gray-mid);margin:0 0 8px">
      Видалити сервер <strong id="delSrvName"></strong>?<br>
    </p>
    <p style="font-size:.78rem;color:var(--gray-light)">Всі сесії аналізу цього сервера також будуть видалені.</p>
    <form method="POST">
      <input type="hidden" name="action" value="delete_server">
      <input type="hidden" name="sid" id="delSrvId">
      <div class="mini-modal-footer">
        <button type="button" class="btn btn-outline btn-sm" onclick="closeModal('delSrvModal')">Скасувати</button>
        <button type="submit" class="btn btn-sm" style="background:var(--red-err);color:#fff;border:none">✕ Видалити</button>
      </div>
    </form>
  </div>
</div>

<?php renderFooter(); ?>
</div>

<script>
// ── Вкладки ──
function switchTab(name) {
  document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.admin-tab').forEach(t => t.classList.remove('active'));
  document.getElementById('tab-' + name).classList.add('active');
  event.target.classList.add('active');
}

// ── Модалки ──
function closeModal(id) { document.getElementById(id).classList.remove('open'); }
function openModal(id)  { document.getElementById(id).classList.add('open'); }

// Закриття кліком на фон
document.querySelectorAll('.mini-modal').forEach(m => {
  m.addEventListener('click', e => { if (e.target === m) m.classList.remove('open'); });
});

function openDelModal(uid, name, srvCount) {
  document.getElementById('delUid').value  = uid;
  document.getElementById('delName').textContent = name;
  document.getElementById('delWarn').textContent = srvCount > 0
    ? `⚠ У користувача ${srvCount} сервер(ів) — вони теж будуть видалені!` : '';
  openModal('delModal');
}
function openRoleModal(uid, name, role) {
  document.getElementById('roleUid').value    = uid;
  document.getElementById('roleName').textContent = name;
  document.getElementById('roleSelect').value = role;
  openModal('roleModal');
}
function openPassModal(uid, name) {
  document.getElementById('passUid').value    = uid;
  document.getElementById('passName').textContent = name;
  document.getElementById('newPassInput').value = '';
  openModal('passModal');
}
function openDelSrvModal(sid, name) {
  document.getElementById('delSrvId').value    = sid;
  document.getElementById('delSrvName').textContent = name;
  openModal('delSrvModal');
}

async function detectGw(sid) {
  const btn = document.getElementById('gw-btn-' + sid);
  const val = document.getElementById('gw-val-' + sid);
  if (!btn || !val) return;

  btn.disabled = true;
  btn.textContent = '⏳…';

  try {
    const fd = new FormData();
    fd.append('action', 'detect_gateway');
    fd.append('sid', sid);
    const r = await fetch('admin.php', { method:'POST', body:fd });
    const d = await r.json();

    if (d.ok) {
      val.innerHTML = `<span style="color:var(--green-ok);font-weight:600">${d.gateway}</span>`;
      btn.textContent = '✓';
      btn.style.background = 'var(--green-ok)';
      btn.style.color = '#fff';
      btn.style.borderColor = 'var(--green-ok)';
      setTimeout(() => {
        btn.textContent = '⟳ SSH';
        btn.style.background = '';
        btn.style.color = '';
        btn.style.borderColor = '';
        btn.disabled = false;
      }, 3000);
    } else {
      val.innerHTML = `<span style="color:var(--red-err);font-size:.7rem" title="${d.error}">Помилка</span>`;
      btn.textContent = '⟳ SSH';
      btn.disabled = false;
    }
  } catch(e) {
    btn.textContent = '⟳ SSH';
    btn.disabled = false;
  }
}
</script>
</body>
</html>
