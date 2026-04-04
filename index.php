<?php
/* ─────────────────────────────────────────────────────
   LogPortal — index.php
   Сторінка авторизації та реєстрації
   ───────────────────────────────────────────────────── */
require_once __DIR__ . '/includes/auth.php';

// Перевірка доступності БД
$dbError = '';
try {
    getDB();
} catch (Throwable $e) {
    $dbError = $e->getMessage();
}

// Якщо вже авторизований — перейти до серверів
if (!$dbError && isAuth()) {
    header('Location: servers.php');
    exit;
}

$error   = '';
$success = '';
$tab     = 'login';

// Читаємо org_name з БД
$orgName = 'УІТ НКРЕКП';
if (!$dbError) {
    try {
        $db = getDB();
        $st = $db->prepare("SELECT value FROM settings WHERE key='org_name'");
        $st->execute();
        $row = $st->fetch(PDO::FETCH_ASSOC);
        if ($row && !empty($row['value'])) $orgName = $row['value'];
    } catch (Throwable $e) {}
}

if (!$dbError && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? 'login';

    if ($action === 'login') {
        $error = doLogin($_POST['username'] ?? '', $_POST['password'] ?? '');
        if (!$error) {
            header('Location: servers.php');
            exit;
        }
        $tab = 'login';
    } elseif ($action === 'register') {
        $error = doRegister(
            $_POST['username'] ?? '',
            $_POST['password'] ?? '',
            $_POST['password2'] ?? '',
            $_POST['email'] ?? ''
        );
        if (!$error) {
            $success = 'Реєстрацію успішно завершено. Тепер увійдіть.';
            $tab = 'login';
        } else {
            $tab = 'register';
        }
    }
}
?>
<!DOCTYPE html>
<html lang="uk">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Авторизація — LogPortal</title>
<link rel="stylesheet" href="css/style.css">
<script>
(function(){var t=localStorage.getItem('lp_theme');if(t)document.documentElement.setAttribute('data-theme',t);})();
</script>
</head>
<body>

<div class="auth-page">

  <!-- gov.ua strip -->
  <div class="govua-strip">
    <div class="container">
      <div class="govua-badge">
        <div class="flag"><div class="flag-blue"></div><div class="flag-yellow"></div></div>
        <?= htmlspecialchars($orgName) ?>
      </div>
    </div>
  </div>

  <div class="auth-body">
    <div class="auth-card">

      <!-- Header -->
      <div class="auth-card-header">
        <div class="auth-logo-wrap">
          <div class="auth-emblem">📊</div>
          <div>
            <div class="auth-title">LogPortal</div>
            <div class="auth-tagline">Портал аналізу серверних журналів</div>
          </div>
        </div>
      </div>

      <!-- Body -->
      <div class="auth-card-body">

        <?php if ($dbError): ?>

          <!-- Помилка БД -->
          <div class="alert alert-error">
            <span class="alert-icon">🗄</span>
            <div>
              <strong>Помилка бази даних — SQLite недоступна</strong><br>
              <small style="font-family:monospace;word-break:break-all"><?= nl2br(htmlspecialchars($dbError)) ?></small>
            </div>
          </div>
          <div class="alert alert-warning">
            <span class="alert-icon">⚠</span>
            <div>
              <strong>Виправлення — виконайте на сервері від root:</strong>
              <pre style="background:var(--blue-pale);padding:10px;border-radius:4px;margin-top:8px;font-size:0.75rem;overflow-x:auto">sudo bash fix_permissions.sh
# або вручну:
sudo mkdir -p /var/www/html/data
sudo chown www-data:www-data /var/www/html/data
sudo chmod 750 /var/www/html/data</pre>
              Потім оновіть сторінку.
            </div>
          </div>

        <?php else: ?>

          <!-- Повідомлення сесії -->
          <?php if (isset($_GET['expired'])): ?>
            <div class="alert alert-warning">
              <span class="alert-icon">⚠</span>
              <span>Сесія завершена. Будь ласка, увійдіть знову.</span>
            </div>
          <?php endif; ?>

          <?php if (isset($_GET['logout'])): ?>
            <div class="alert alert-success">
              <span class="alert-icon">✓</span>
              <span>Ви успішно вийшли з системи.</span>
            </div>
          <?php endif; ?>

          <?php if ($error): ?>
            <div class="alert alert-error">
              <span class="alert-icon">✕</span>
              <span><?= htmlspecialchars($error) ?></span>
            </div>
          <?php endif; ?>

          <?php if ($success): ?>
            <div class="alert alert-success">
              <span class="alert-icon">✓</span>
              <span><?= htmlspecialchars($success) ?></span>
            </div>
          <?php endif; ?>

          <!-- Tabs -->
          <div class="auth-tabs">
            <button class="auth-tab <?= $tab === 'login'    ? 'active' : '' ?>" onclick="switchTab('login')">Вхід до системи</button>
            <button class="auth-tab <?= $tab === 'register' ? 'active' : '' ?>" onclick="switchTab('register')">Реєстрація</button>
          </div>

          <!-- Login panel -->
          <div id="panel-login" class="auth-panel <?= $tab === 'login' ? 'active' : '' ?>">
            <form method="POST" autocomplete="on">
              <input type="hidden" name="action" value="login">
              <div class="form-group">
                <label class="form-label">Логін <span class="req">*</span></label>
                <input type="text" name="username" class="form-control"
                       placeholder="Ваш логін"
                       value="<?= htmlspecialchars($_POST['username'] ?? '') ?>"
                       autocomplete="username" required>
              </div>
              <div class="form-group">
                <label class="form-label">Пароль <span class="req">*</span></label>
                <input type="password" name="password" class="form-control"
                       placeholder="••••••••"
                       autocomplete="current-password" required>
              </div>
              <button type="submit" class="btn btn-primary btn-block btn-lg" style="margin-top:20px">
                → Увійти до системи
              </button>
            </form>
          </div>

          <!-- Register panel -->
          <div id="panel-register" class="auth-panel <?= $tab === 'register' ? 'active' : '' ?>">
            <form method="POST" autocomplete="off">
              <input type="hidden" name="action" value="register">
              <div class="form-group">
                <label class="form-label">Логін <span class="req">*</span></label>
                <input type="text" name="username" class="form-control"
                       placeholder="Мін. 3 символи, a-z 0-9 _" required>
                <div class="form-hint">Лише латинські літери, цифри та символ _</div>
              </div>
              <div class="form-group">
                <label class="form-label">Email</label>
                <input type="email" name="email" class="form-control"
                       placeholder="user@example.com">
              </div>
              <div class="form-row">
                <div class="form-group" style="margin-bottom:0">
                  <label class="form-label">Пароль <span class="req">*</span></label>
                  <input type="password" name="password" class="form-control"
                         placeholder="Мін. 6 символів" required>
                </div>
                <div class="form-group" style="margin-bottom:0">
                  <label class="form-label">Повтор <span class="req">*</span></label>
                  <input type="password" name="password2" class="form-control"
                         placeholder="Повторіть пароль" required>
                </div>
              </div>
              <button type="submit" class="btn btn-success btn-block btn-lg" style="margin-top:24px">
                ✓ Зареєструватись
              </button>
            </form>
          </div>

        <?php endif; /* $dbError */ ?>

      </div><!-- /.auth-card-body -->

      <div class="auth-footer">
        За замовчуванням: логін&nbsp;<code>admin</code>&nbsp;/&nbsp;пароль&nbsp;<code>admin123</code>
        &nbsp;·&nbsp;Змініть після першого входу
        <div style="margin-top:10px">
          <button class="theme-toggle" id="themeToggle" onclick="toggleTheme()" style="margin:0 auto">
            <span class="theme-toggle-icon" id="themeIcon">🌙</span>
            <span id="themeLabel">Темна тема</span>
          </button>
        </div>
      </div>

    </div><!-- /.auth-card -->
  </div><!-- /.auth-body -->

</div><!-- /.auth-page -->

<script>
function switchTab(tab) {
  document.querySelectorAll('.auth-tab').forEach((t, i) => {
    t.classList.toggle('active', (tab === 'login' && i === 0) || (tab === 'register' && i === 1));
  });
  document.getElementById('panel-login').classList.toggle('active', tab === 'login');
  document.getElementById('panel-register').classList.toggle('active', tab === 'register');
}
function applyTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme);
  var icon  = document.getElementById('themeIcon');
  var label = document.getElementById('themeLabel');
  if (!icon || !label) return;
  if (theme === 'dark') { icon.textContent = '☀️'; label.textContent = 'Світла тема'; }
  else                  { icon.textContent = '🌙'; label.textContent = 'Темна тема'; }
}
function toggleTheme() {
  var next = (document.documentElement.getAttribute('data-theme') === 'dark') ? 'light' : 'dark';
  localStorage.setItem('lp_theme', next);
  applyTheme(next);
}
applyTheme(localStorage.getItem('lp_theme') || 'light');
</script>
</body>
</html>
