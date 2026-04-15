<?php
/* ─────────────────────────────────────────────────────
   LogPortal — server_add.php
   Додавання / редагування SSH-сервера
   ───────────────────────────────────────────────────── */
require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/layout.php';
require_once __DIR__ . '/includes/ssh.php';
requireAuth();
sendSecurityHeaders();
$user = currentUser();
$db   = getDB();

// ─── Режим редагування ───
$editId = (int)($_GET['edit'] ?? 0);
$srv    = null;
if ($editId) {
    $st = $db->prepare("SELECT * FROM servers WHERE id=? AND user_id=?");
    $st->execute([$editId, $user['id']]);
    $srv = $st->fetch();
    if (!$srv) { header('Location: servers.php'); exit; }
}
$isEdit = $srv !== null;

$error   = '';
$success = '';
$testMsg   = '';
$testOk    = false;
$testDebug = '';

// ─── Обробка форми ───
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action    = $_POST['_action'] ?? 'save';
    $name      = trim($_POST['name']     ?? '');
    $host      = trim($_POST['host']     ?? '');
    $port      = (int)($_POST['port']    ?? 22);
    $sshUser   = trim($_POST['ssh_user'] ?? '');
    $authType  = $_POST['auth_type']     ?? 'password';
    $sshPass   = $_POST['ssh_password']  ?? '';
    $keyPass   = $_POST['key_passphrase']?? '';
    $desc         = trim($_POST['description']   ?? '');
    $deviceType   = $_POST['device_type']         ?? 'linux';
    $detectGw     = !empty($_POST['detect_gateway']);
    $gatewayInput = trim($_POST['gateway']         ?? '');
    if (!in_array($deviceType, ['linux','mikrotik'])) $deviceType = 'linux';

    // Завантаження ключа
    $keyPath = $isEdit ? ($srv['key_path'] ?? '') : '';
    if ($authType === 'key' && !empty($_FILES['ssh_key']['tmp_name'])) {
        $dir = KEY_UPLOAD_DIR;
        if (!is_dir($dir)) mkdir($dir, 0700, true);
        $fname   = 'key_' . $user['id'] . '_' . time() . '_' . preg_replace('/[^a-zA-Z0-9._-]/', '', $_FILES['ssh_key']['name']);
        $keyPath = $dir . $fname;
        if (!move_uploaded_file($_FILES['ssh_key']['tmp_name'], $keyPath)) {
            $error = 'Не вдалось завантажити файл ключа';
        } else {
            chmod($keyPath, 0600);
        }
    }

    if (!$error) {
        // Валідація
        if (!$name)    $error = 'Введіть назву сервера';
        elseif (!$host) $error = 'Введіть хост або IP-адресу';
        elseif (!$sshUser) $error = 'Введіть SSH-логін';
        elseif ($port < 1 || $port > 65535) $error = 'Невірний порт (1–65535)';
        elseif ($authType === 'password' && !$sshPass && !$isEdit) $error = 'Введіть SSH-пароль';
        elseif ($authType === 'key' && !$keyPath) $error = 'Завантажте SSH-ключ';
    }

    if (!$error) {
        // Тест підключення перед збереженням
        $testSrv = [
            'host' => $host, 'port' => $port, 'ssh_user' => $sshUser,
            'auth_type' => $authType,
            'ssh_password' => $sshPass ? encrypt($sshPass) : ($isEdit ? $srv['ssh_password'] : ''),
            'key_path' => $keyPath,
            'key_passphrase' => $keyPass ? encrypt($keyPass) : ($isEdit ? $srv['key_passphrase'] : ''),
        ];
        $conn = sshConnect($testSrv);

        if ($action === 'test') {
            $testOk    = $conn['success'];
            $testMsg   = $conn['success'] ? 'Підключення успішне!' : ($conn['error'] ?? 'Помилка підключення');
            $testDebug = $conn['debug'] ?? '';
        } else {
            // Збереження
            $status    = $conn['success'] ? 'online' : 'offline';
            $encPass   = $sshPass ? encrypt($sshPass) : ($isEdit ? $srv['ssh_password'] : null);
            $encKeyPas = $keyPass ? encrypt($keyPass) : ($isEdit ? $srv['key_passphrase'] : null);

            // Визначення gateway через SSH (тільки Linux + чекбокс + успішне підключення)
            $gateway = $gatewayInput;
            if ($detectGw && $conn['success'] && $deviceType === 'linux') {
                $detected = detectGateway($conn);
                if ($detected !== '') $gateway = $detected;
            }

            if ($isEdit) {
                $db->prepare("UPDATE servers SET
                    name=?, host=?, port=?, ssh_user=?, auth_type=?,
                    ssh_password=?, key_path=?, key_passphrase=?,
                    description=?, device_type=?, gateway=?, status=?, last_check=CURRENT_TIMESTAMP
                    WHERE id=? AND user_id=?")
                ->execute([$name,$host,$port,$sshUser,$authType,$encPass,
                           $keyPath ?: $srv['key_path'],$encKeyPas,$desc,
                           $deviceType,$gateway,$status,$editId,$user['id']]);
                header('Location: servers.php?msg=' . urlencode('Сервер оновлено') . '&mt=success');
            } else {
                $db->prepare("INSERT INTO servers
                    (user_id,name,host,port,ssh_user,auth_type,ssh_password,key_path,key_passphrase,description,device_type,gateway,status,last_check)
                    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,CURRENT_TIMESTAMP)")
                ->execute([$user['id'],$name,$host,$port,$sshUser,$authType,$encPass,$keyPath,$encKeyPas,$desc,$deviceType,$gateway,$status]);
                header('Location: servers.php?msg=' . urlencode('Сервер додано') . '&mt=success');
            }
            exit;
        }
    }
}

$f = $_POST + ($srv ?? []);   // зручне злиття для value-атрибутів
?>
<!DOCTYPE html>
<html lang="uk">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title><?= $isEdit ? 'Редагувати сервер' : 'Додати сервер' ?> — LogPortal</title>
<link rel="stylesheet" href="css/style.css">
<script>
(function(){var t=localStorage.getItem('lp_theme');if(t)document.documentElement.setAttribute('data-theme',t);})();
</script>
</head>
<body>
<div class="page-wrap">

  <!-- gov.ua strip -->
  <?php renderGovStrip(); renderHeader($user); renderNav($user, 'add'); ?>
  <div class="breadcrumbs">
    <div class="container">
      <a href="servers.php">Сервери</a>
      <span class="bc-sep">›</span>
      <span class="bc-current"><?= $isEdit ? 'Редагувати: ' . htmlspecialchars($srv['name']) : 'Додати новий сервер' ?></span>
    </div>
  </div>

  <main class="page-content">
    <div class="container" style="max-width:720px">

      <div class="page-title-block">
        <div class="page-title-text">
          <h1><?= $isEdit ? '✏ Редагувати сервер' : '➕ Додати SSH-сервер' ?></h1>
          <div class="subtitle">Підключення до Linux/MikroTik пристрою для аналізу логів</div>
        </div>
      </div>

      <?php if ($error): ?>
        <div class="alert alert-error"><span class="alert-icon">✕</span> <?= htmlspecialchars($error) ?></div>
      <?php endif; ?>

      <?php if ($testMsg): ?>
        <div class="alert alert-<?= $testOk ? 'success' : 'error' ?>">
          <span class="alert-icon"><?= $testOk ? '✓' : '✕' ?></span>
          <div><strong><?= $testOk ? 'Підключення успішне!' : 'Помилка підключення' ?></strong><br>
          <?= nl2br(htmlspecialchars($testMsg)) ?></div>
        </div>
        <?php if (!empty($testDebug) && isset($testDebug)): ?>
        <div class="card" style="border-left:3px solid var(--orange-warn);margin-bottom:16px">
          <div class="card-header" style="cursor:pointer" onclick="this.nextElementSibling.classList.toggle('d-none')">
            <div class="card-header-title">🔍 Діагностика SSH (натисніть щоб розгорнути)</div>
          </div>
          <div class="card-body d-none">
            <pre style="background:#1a1a2e;color:#00d4aa;padding:12px;border-radius:4px;font-size:0.72rem;overflow-x:auto;white-space:pre-wrap"><?= htmlspecialchars($testDebug ?? '') ?></pre>
            <div style="margin-top:12px;font-size:0.78rem;color:var(--gray-mid)">
              <strong>Поширені причини помилки ключа:</strong><br>
              &bull; Ключ не у форматі PEM — конвертуйте: <code>ssh-keygen -p -f key -m PEM -N &quot;&quot;</code><br>
              &bull; Неправильні права: <code>chmod 600 /шлях/до/ключа</code><br>
              &bull; Публічний ключ відсутній у <code>~/.ssh/authorized_keys</code> на сервері<br>
              &bull; Сервер не дозволяє key auth — перевірте <code>PubkeyAuthentication yes</code> в sshd_config
            </div>
          </div>
        </div>
        <?php endif; ?>
      <?php endif; ?>

      <form method="POST" enctype="multipart/form-data">
        <input type="hidden" name="_action" id="formAction" value="save">

        <!-- Основна інформація -->
        <div class="card mb-4">
          <div class="card-header">
            <div class="card-header-title">🖥️ Основна інформація</div>
          </div>
          <div class="card-body">
            <div class="form-group">
              <label class="form-label">Назва сервера <span class="req">*</span></label>
              <input type="text" name="name" class="form-control"
                     placeholder="Наприклад: Web Server Production"
                     value="<?= htmlspecialchars($f['name'] ?? '') ?>" required>
            </div>
            <!-- Тип пристрою -->
            <div class="form-group">
              <label class="form-label">Тип пристрою <span class="req">*</span></label>
              <div class="radio-tabs">
                <div class="radio-tab">
                  <input type="radio" name="device_type" id="dt_linux" value="linux"
                         <?= ($f['device_type'] ?? 'linux') === 'linux' ? 'checked' : '' ?>
                         onchange="updateDeviceHints('linux')">
                  <label for="dt_linux">🐧 Linux / Unix</label>
                </div>
                <div class="radio-tab">
                  <input type="radio" name="device_type" id="dt_mikrotik" value="mikrotik"
                         <?= ($f['device_type'] ?? '') === 'mikrotik' ? 'checked' : '' ?>
                         onchange="updateDeviceHints('mikrotik')">
                  <label for="dt_mikrotik">🔶 MikroTik RouterOS</label>
                </div>
              </div>
              <div id="hint_linux" style="font-size:.75rem;color:var(--gray-mid);margin-top:6px">
                Nginx, Apache, Postfix, BIND логи. Читання через bash (find/cat/grep).
              </div>
              <div id="hint_mikrotik" style="font-size:.75rem;color:var(--orange-warn);margin-top:6px;display:none">
                RouterOS логи читаються через <code>/log print</code>. Переконайтесь що SSH увімкнено: <strong>IP → Services → SSH</strong>.
                Логін — будь-який RouterOS-юзер з правом <strong>read</strong>.
              </div>
            </div>

            <div class="form-row-3">
              <div class="form-group" style="margin-bottom:0">
                <label class="form-label">Хост / IP-адреса <span class="req">*</span></label>
                <input type="text" name="host" class="form-control"
                       placeholder="192.168.1.10 або server.example.com"
                       value="<?= htmlspecialchars($f['host'] ?? '') ?>" required>
              </div>
              <div class="form-group" style="margin-bottom:0">
                <label class="form-label">SSH Порт <span class="req">*</span></label>
                <input type="number" name="port" class="form-control"
                       min="1" max="65535" value="<?= (int)($f['port'] ?? 22) ?>" required>
              </div>
              <div class="form-group" style="margin-bottom:0">
                <label class="form-label">SSH Логін <span class="req">*</span></label>
                <input type="text" name="ssh_user" class="form-control"
                       placeholder="root"
                       value="<?= htmlspecialchars($f['ssh_user'] ?? '') ?>" required>
              </div>
            </div>
            <div class="form-group mt-3">
              <label class="form-label">Опис (необов'язково)</label>
              <input type="text" name="description" class="form-control"
                     placeholder="Короткий опис сервера"
                     value="<?= htmlspecialchars($f['description'] ?? '') ?>">
            </div>

            <!-- Gateway -->
            <div class="form-group mt-3" id="gwBlock">
              <label class="form-label">Gateway (шлюз за замовчуванням)</label>
              <div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap">
                <input type="text" name="gateway" id="gatewayInput" class="form-control"
                       placeholder="Визначається автоматично або введіть вручну"
                       style="max-width:240px"
                       value="<?= htmlspecialchars($f['gateway'] ?? $srv['gateway'] ?? '') ?>">
                <label style="display:flex;align-items:center;gap:6px;font-size:.83rem;cursor:pointer;user-select:none">
                  <input type="checkbox" name="detect_gateway" id="detectGwCheck" value="1"
                         <?= !empty($f['detect_gateway']) ? 'checked' : '' ?>
                         style="width:15px;height:15px;cursor:pointer;accent-color:var(--blue-main)">
                  Визначити автоматично через SSH
                </label>
                <span id="gwStatus" style="font-size:.78rem;color:var(--gray-mid)"></span>
              </div>
              <div style="font-size:.72rem;color:var(--gray-mid);margin-top:4px">
                Тільки для Linux. Виконується після успішного SSH-підключення.
              </div>
            </div>

          </div>
        </div>

        <!-- Автентифікація -->
        <div class="card mb-4">
          <div class="card-header">
            <div class="card-header-title">🔐 Метод автентифікації</div>
          </div>
          <div class="card-body">

            <div class="radio-tabs">
              <div class="radio-tab">
                <input type="radio" name="auth_type" id="auth_pass" value="password"
                       <?= ($f['auth_type'] ?? 'password') === 'password' ? 'checked' : '' ?>
                       onchange="toggleAuth('password')">
                <label for="auth_pass">🔑 Пароль</label>
              </div>
              <div class="radio-tab">
                <input type="radio" name="auth_type" id="auth_key" value="key"
                       <?= ($f['auth_type'] ?? '') === 'key' ? 'checked' : '' ?>
                       onchange="toggleAuth('key')">
                <label for="auth_key">🔐 SSH Ключ</label>
              </div>
            </div>

            <!-- Password block -->
            <div id="block-password" style="display:<?= ($f['auth_type']??'password')==='password'?'block':'none' ?>">
              <div class="form-group" style="margin-bottom:0">
                <label class="form-label">SSH Пароль <?= !$isEdit?'<span class="req">*</span>':'' ?></label>
                <input type="password" name="ssh_password" class="form-control"
                       placeholder="<?= $isEdit ? '(залишіть порожнім — без змін)' : 'Пароль SSH' ?>"
                       autocomplete="new-password">
                <?php if ($isEdit): ?>
                  <div class="form-hint">Залишіть порожнім, щоб не змінювати пароль</div>
                <?php endif; ?>
              </div>
            </div>

            <!-- Key block -->
            <div id="block-key" style="display:<?= ($f['auth_type']??'')==='key'?'block':'none' ?>">
              <div class="form-group">
                <label class="form-label">Приватний SSH-ключ <?= !$isEdit?'<span class="req">*</span>':'' ?></label>
                <div class="file-drop" onclick="document.getElementById('keyFile').click()"
                     ondragover="this.classList.add('dragover');event.preventDefault()"
                     ondragleave="this.classList.remove('dragover')"
                     ondrop="handleDrop(event)">
                  <input type="file" name="ssh_key" id="keyFile" accept=".pem,.key,.ppk,*"
                         onchange="showFileName(this)">
                  <div class="file-drop-icon">📎</div>
                  <div class="file-drop-text">
                    <strong>Виберіть файл</strong> або перетягніть сюди<br>
                    Підтримуються RSA, Ed25519, ECDSA (.pem, .key)
                  </div>
                  <div class="file-name-display" id="fileName">
                    <?= $isEdit && $srv['key_path'] ? '📎 ' . htmlspecialchars(basename($srv['key_path'])) : '' ?>
                  </div>
                </div>
              </div>
              <div class="form-group" style="margin-bottom:0">
                <label class="form-label">Парольна фраза ключа (якщо є)</label>
                <input type="password" name="key_passphrase" class="form-control"
                       placeholder="(необов'язково)" autocomplete="new-password">
              </div>
            </div>

          </div>
        </div>

        <!-- Actions -->
        <div class="flex gap-3" style="margin-top:8px">
          <button type="button" class="btn btn-outline" onclick="testConnection()">
            🔌 Перевірити підключення
          </button>
          <button type="submit" class="btn btn-primary btn-lg" style="flex:1;justify-content:center">
            <?= $isEdit ? '💾 Зберегти зміни' : '➕ Додати сервер' ?>
          </button>
          <a href="servers.php" class="btn btn-outline">Скасувати</a>
        </div>

      </form>

      <!-- SSH Info card -->
      <div class="card mt-6" style="border-left:3px solid var(--blue-main)">
        <div class="card-body" style="padding:14px 18px">
          <div style="font-size:0.8rem;color:var(--gray-mid)">
            <strong style="color:var(--blue-dark)">📋 Вимоги до SSH-підключення:</strong><br>
            Для авторизації паролем: <code style="background:var(--blue-pale);padding:1px 5px;border-radius:3px">apt install sshpass</code>&nbsp;&nbsp;
            Для нативного SSH: <code style="background:var(--blue-pale);padding:1px 5px;border-radius:3px">apt install php-ssh2</code><br>
            Ключі зберігаються з правами 600 у захищеній директорії.
          </div>
        </div>
      </div>

    </div>
  </main>

  <?php renderFooter(); ?>

</div>

<script>
function updateDeviceHints(type) {
  document.getElementById('hint_linux').style.display    = type==='linux'    ? 'block' : 'none';
  document.getElementById('hint_mikrotik').style.display = type==='mikrotik' ? 'block' : 'none';
}
function toggleAuth(type) {
  document.getElementById('block-password').style.display = type==='password'?'block':'none';
  document.getElementById('block-key').style.display = type==='key'?'block':'none';
}
function testConnection() {
  document.getElementById('formAction').value = 'test';
  document.querySelector('form').submit();
}
function showFileName(inp) {
  const d = document.getElementById('fileName');
  if (inp.files[0]) {
    d.textContent = '📎 ' + inp.files[0].name;
    d.style.display = 'block';
  }
}
function handleDrop(e) {
  e.preventDefault();
  e.currentTarget.classList.remove('dragover');
  const dt = e.dataTransfer;
  if (dt.files[0]) {
    document.getElementById('keyFile').files = dt.files;
    showFileName(document.getElementById('keyFile'));
  }
}

// Приховуємо gateway блок для MikroTik
function toggleDeviceType(type) {
  const gwBlock = document.getElementById('gwBlock');
  if (gwBlock) gwBlock.style.display = type === 'mikrotik' ? 'none' : 'block';
}

// Ініціалізація при завантаженні
document.addEventListener('DOMContentLoaded', function() {
  const dtLinux = document.getElementById('dt_linux');
  const dtMt    = document.getElementById('dt_mikrotik');
  if (dtLinux)  dtLinux.addEventListener('change',   () => toggleDeviceType('linux'));
  if (dtMt)     dtMt.addEventListener('change',      () => toggleDeviceType('mikrotik'));
  // Встановлюємо початковий стан
  const curType = document.querySelector('input[name="device_type"]:checked')?.value || 'linux';
  toggleDeviceType(curType);
});
</script>
</body>
</html>
