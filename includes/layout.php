<?php
/* LogPortal — layout.php
   Спільні компоненти сторінок: header, nav, footer
*/

function renderGovStrip(): void {
    $orgName = 'УІТ НКРЕКП';
    try {
        $db = getDB();
        $r  = $db->query("SELECT value FROM settings WHERE key='org_name'");
        $v  = $r ? $r->fetchColumn() : false;
        if ($v !== false && trim($v) !== '') $orgName = trim($v);
    } catch (\Throwable $e) {}
    ?>
<div class="govua-strip"><div class="container"><div class="govua-badge">
  <div class="flag"><div class="flag-blue"></div><div class="flag-yellow"></div></div>
  <?= htmlspecialchars($orgName) ?>
</div></div></div>
<?php }

function renderHeader(array $user): void { ?>
<header class="site-header"><div class="container"><div class="header-inner">
  <a href="servers.php" class="header-logo">
    <div class="logo-emblem">📊</div>
    <div class="logo-text-wrap">
      <div class="logo-title">LogPortal</div>
      <div class="logo-subtitle">Портал аналізу серверних журналів</div>
    </div>
  </a>
  <div class="header-user">
    <button class="theme-toggle" id="themeToggle" onclick="toggleTheme()" title="Змінити тему">
      <span class="theme-toggle-icon" id="themeIcon">🌙</span>
      <span id="themeLabel">Темна</span>
    </button>
    <div class="user-chip">
      <div class="user-avatar"><?= strtoupper(substr(htmlspecialchars($user['username']),0,1)) ?></div>
      <?= htmlspecialchars($user['username']) ?>
    </div>
    <a href="logout.php" class="btn-logout">✕ Вийти</a>
  </div>
</div></div></header>
<?php }

function renderNav(array $user, string $active = '', int $sid = 0): void {
    $sidQ = $sid ? "?sid=$sid" : '';
    ?>
<nav class="site-nav"><div class="container">
  <a href="servers.php"   class="nav-link <?= $active==='servers'  ? 'active':'' ?>">⌖ Сервери</a>
  <?php if ($sid): ?>
  <a href="logs.php<?= $sidQ ?>" class="nav-link <?= $active==='logs' ? 'active':'' ?>">📂 Файли</a>
  <a href="mail_search.php<?= $sidQ ?>" class="nav-link <?= $active==='mail' ? 'active':'' ?>">✉ Пошта</a>
  <?php endif; ?>
  <a href="threats.php<?= $sidQ ?>" class="nav-link <?= $active==='threats' ? 'active':'' ?>">🛡 Загрози</a>
  <a href="vpn.php<?= $sidQ ?>" class="nav-link <?= $active==='vpn' ? 'active':'' ?>">🔐 VPN</a>
  <a href="address_list.php<?= $sidQ ?>" class="nav-link <?= $active==='addrlist' ? 'active':'' ?>">📋 Address List</a>
  <a href="server_add.php" class="nav-link <?= $active==='add' ? 'active':'' ?>">＋ Додати сервер</a>
  <?php if ($user['role'] === 'admin'): ?>
  <a href="admin.php" class="nav-link <?= $active==='admin' ? 'active':'' ?>" style="margin-left:auto">⚙ Адмін</a>
  <?php endif; ?>
</div></nav>
<?php }

function renderFooter(): void { ?>
<footer class="site-footer"><div class="container">
  <div class="footer-logo">LogPortal v2.0.1</div>
  <div>Аналіз Nginx · Postfix · BIND та VPN логів &copy; <?= date('Y') ?>
    &nbsp;·&nbsp;<a href="mailto:admin@nerc.gov.ua" style="color:inherit;opacity:.7">admin@nerc.gov.ua</a>
  </div>
</div></footer>
<script>
// ── Theme management ──────────────────────────────────────────────────────
function applyTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme);
  var icon  = document.getElementById('themeIcon');
  var label = document.getElementById('themeLabel');
  if (!icon || !label) return;
  if (theme === 'dark') {
    icon.textContent  = '☀️';
    label.textContent = 'Світла';
  } else {
    icon.textContent  = '🌙';
    label.textContent = 'Темна';
  }
}
function toggleTheme() {
  var cur = document.documentElement.getAttribute('data-theme') || 'light';
  var next = cur === 'dark' ? 'light' : 'dark';
  localStorage.setItem('lp_theme', next);
  applyTheme(next);
}
// Ініціалізація — до відображення сторінки (уникаємо мигання)
(function() {
  var saved = localStorage.getItem('lp_theme') || 'light';
  applyTheme(saved);
})();
</script>
<?php }
