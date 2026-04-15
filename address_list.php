<?php
require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/layout.php';
require_once __DIR__ . '/includes/ssh.php';
requireAuth();
sendSecurityHeaders();
$user = currentUser();
$db   = getDB();

$sid = (int)($_GET['sid'] ?? 0);

// ── Отримуємо всі MikroTik сервери ──
$servers = $db->query(
    "SELECT id, name, host, port, ssh_user, auth_type, ssh_password, key_path, key_passphrase, device_type
     FROM servers WHERE device_type='mikrotik' ORDER BY name"
)->fetchAll(PDO::FETCH_ASSOC);

$srv = null;
if ($sid) {
    foreach ($servers as $s) {
        if ((int)$s['id'] === $sid) { $srv = $s; break; }
    }
    if (!$srv) $sid = 0;
}

// ── AJAX дії ──
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
    header('Content-Type: application/json');

    if (!$srv) {
        echo json_encode(['ok' => false, 'error' => 'Сервер не вибрано']);
        exit;
    }

    // Підключення
    $conn = sshConnect($srv);

    if (!$conn || (!isset($conn['conn']) && !isset($conn['shell']))) {
        echo json_encode(['ok' => false, 'error' => 'SSH підключення не вдалось']);
        exit;
    }

    $action = $_POST['action'];

    // ── Отримати список ──
    if ($action === 'get_lists') {
        // Використовуємо звичайний print — він дає табличний вивід з коментарями ;;;
        $raw   = sshExecMikrotik($conn, '/ip firewall address-list print without-paging');
        $lists = parseAddressListOutput($raw);
        echo json_encode(['ok' => true, 'lists' => $lists, 'raw' => $raw]);
        exit;
    }

    // ── Додати IP ──
    if ($action === 'add_ip') {
        $list    = trim($_POST['list']    ?? '');
        $address = trim($_POST['address'] ?? '');
        $comment = trim($_POST['comment'] ?? '');

        $comment = trim($_POST['comment'] ?? '');
        $timeout = trim($_POST['timeout'] ?? '');

        if (!$list || !$address) {
            echo json_encode(['ok' => false, 'error' => 'Вкажіть список та IP адресу']);
            exit;
        }

        // Валідація IP/CIDR
        if (!preg_match('/^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/', $address)) {
            echo json_encode(['ok' => false, 'error' => 'Невірний формат IP (очікується x.x.x.x або x.x.x.x/xx)']);
            exit;
        }

        // Валідація таймауту (якщо вказано)
        if ($timeout !== '' && !preg_match('/^(\d+[wdhms]\s*)+$|^\d+d\s+\d{2}:\d{2}:\d{2}$/i', $timeout)) {
            echo json_encode(['ok' => false, 'error' => 'Невірний формат таймауту (приклад: 10d 00:00:00 або 1w2d)']);
            exit;
        }

        $cmd = '/ip firewall address-list add list=' . escapeMikrotikArg($list)
             . ' address=' . escapeMikrotikArg($address);
        if ($comment !== '') {
            $cmd .= ' comment=' . escapeMikrotikArg($comment);
        }
        if ($timeout !== '') {
            $cmd .= ' timeout=' . escapeMikrotikArg($timeout);
        }

        $out = sshExecMikrotik($conn, $cmd);
        $err = detectMikrotikError($out);
        if ($err) {
            echo json_encode(['ok' => false, 'error' => $err]);
        } else {
            $typeLabel = $timeout !== '' ? "dynamic (таймаут: {$timeout})" : 'static';
            echo json_encode(['ok' => true, 'message' => "IP {$address} додано до «{$list}» як {$typeLabel}"]);
        }
        exit;
    }

    // ── Видалити IP ──
    if ($action === 'remove_ip') {
        $entryId = trim($_POST['entry_id'] ?? '');
        $address = trim($_POST['address']  ?? '');
        $list    = trim($_POST['list']     ?? '');

        if (!$entryId) {
            echo json_encode(['ok' => false, 'error' => 'Не вказано ID запису']);
            exit;
        }

        $cmd = '/ip firewall address-list remove ' . escapeMikrotikArg($entryId);
        $out = sshExecMikrotik($conn, $cmd);
        $err = detectMikrotikError($out);
        if ($err) {
            echo json_encode(['ok' => false, 'error' => $err]);
        } else {
            echo json_encode(['ok' => true, 'message' => "IP {$address} видалено зі списку «{$list}»"]);
        }
        exit;
    }

    echo json_encode(['ok' => false, 'error' => 'Невідома дія']);
    exit;
}

// ── Хелпери ──
function escapeMikrotikArg(string $s): string {
    // RouterOS: якщо є пробіли або спецсимволи — беремо в лапки
    if (preg_match('/[\s\[\]{}()!@#$%^&*=+|;:\'",<>?\/\\\\]/', $s)) {
        return '"' . str_replace('"', '\\"', $s) . '"';
    }
    return $s;
}

function detectMikrotikError(string $out): string {
    $out = strtolower(trim($out));
    if (str_contains($out, 'bad command') || str_contains($out, 'syntax error')) {
        return 'Синтаксична помилка команди';
    }
    if (str_contains($out, 'failure:') || str_contains($out, 'error')) {
        return trim($out);
    }
    if (str_contains($out, 'already have such entry')) {
        return 'Такий запис вже існує';
    }
    return '';
}

/**
 * Парсинг /ip firewall address-list print detail without-paging
 * Кожен запис виглядає так:
 *  0 D  list=blocklist address=1.2.3.4 creation-time=jan/01/2026 00:00:00
 *  1    list="port scanners" address=5.6.7.8/24 comment="bad host"
 * Поля можуть бути на одному або кількох рядках з відступом
 */
function parseAddressListDetail(string $raw): array {
    $entries = [];

    $lines   = explode("\n", $raw);
    $current = '';
    $blocks  = [];

    foreach ($lines as $line) {
        $line = rtrim($line);
        if ($line === '') continue;
        if (preg_match('/^\s{0,4}\d+[\s;]/', $line)) {
            if ($current !== '') $blocks[] = $current;
            $current = $line;
        } else {
            $current .= ' ' . ltrim($line);
        }
    }
    if ($current !== '') $blocks[] = $current;

    foreach ($blocks as $block) {
        $block = preg_replace('/\s+/', ' ', trim($block));

        // Номер і флаги: "0 D  list=..." або "1    list=..."
        if (!preg_match('/^(\d+)\s*([XDIS]{0,3})\s+(.+)$/', $block, $hm)) continue;
        $id      = $hm[1];
        $flags   = $hm[2];
        $rest    = $hm[3];
        $disabled = str_contains($flags, 'X');
        $dynamic  = str_contains($flags, 'D');

        // Парсимо key=value або key="value with spaces"
        // RouterOS: list="port scanners" address=1.2.3.4 comment="some text"
        $fields = parseMikrotikFields($rest);

        $listName = trim($fields['list']    ?? '');
        $address  = trim($fields['address'] ?? '');
        if ($listName === '' || $address === '') continue;

        // creation-time: RouterOS виводить "jan/01/2026 00:00:00" — два токени
        $created = '';
        if (preg_match('/creation-time=(\w{3}\/\d{2}\/\d{4})\s+(\d{2}:\d{2}:\d{2})/', $block, $ctm)) {
            $created = $ctm[1] . ' ' . $ctm[2];
        } elseif (!empty($fields['creation-time'])) {
            $created = $fields['creation-time'];
        }

        $entries[] = [
            'id'       => $id,
            'list'     => $listName,
            'address'  => $address,
            'disabled' => $disabled,
            'dynamic'  => $dynamic,
            'created'  => $created,
            'timeout'  => trim($fields['timeout'] ?? ''),
            'comment'  => trim($fields['comment'] ?? ''),
        ];
    }
    return $entries;
}

/**
 * Парсить рядок RouterOS виду: key=value key2="value with spaces" key3=plain
 * Повертає асоціативний масив полів
 */
function parseMikrotikFields(string $s): array {
    $fields = [];

    // Спочатку шукаємо list= окремо, бо значення може містити пробіли без лапок
    // Знаходимо address= як якір — між list= і address= є назва списку
    if (preg_match('/\blist=("([^"]*)"|([^\s=]+(?:\s+[^\s=]+)*))\s+address=/i', $s, $lm)) {
        $fields['list'] = $lm[2] !== '' ? $lm[2] : rtrim($lm[3]);
    } elseif (preg_match('/\blist=("([^"]*)"|(\S+))/i', $s, $lm)) {
        $fields['list'] = $lm[2] !== '' ? $lm[2] : $lm[3];
    }

    // address= завжди без пробілів (IP або CIDR)
    if (preg_match('/\baddress=(\S+)/i', $s, $m)) {
        $fields['address'] = $m[1];
    }

    // timeout= без пробілів
    if (preg_match('/\btimeout=(\S+)/i', $s, $m)) {
        $fields['timeout'] = $m[1];
    }

    // comment= може бути в лапках або без
    if (preg_match('/\bcomment="([^"]*)"/i', $s, $m)) {
        $fields['comment'] = $m[1];
    } elseif (preg_match('/\bcomment=(\S+)/i', $s, $m)) {
        $fields['comment'] = $m[1];
    }

    // creation-time= обробляється окремо в parseAddressListDetail

    return $fields;
}

function parseAddressListOutput(string $raw): array {
    $entries = [];
    $lines   = explode("\n", $raw);
    $n       = count($lines);
    $i       = 0;

    // Дата: RouterOS старий "mar/18/2026 09:20:15" або новий "2026-03-17 20:51:15"
    $dateRe = '(?:\w{3}\/\d{2}\/\d{4}|\d{4}-\d{2}-\d{2})\s+\d{2}:\d{2}:\d{2}';

    while ($i < $n) {
        $line = rtrim($lines[$i]);
        $i++;
        if ($line === '') continue;

        // Рядок з номером: "17 D port scanners  ..." або "32 D ;;; comment"
        if (!preg_match('/^\s{0,4}(\d+)\s*([XDIS]{0,3})\s*(.*)$/', $line, $hm)) continue;

        $id       = $hm[1];
        $flags    = $hm[2];
        $rest     = trim($hm[3]);
        $disabled = str_contains($flags, 'X');
        $dynamic  = str_contains($flags, 'D');
        $comment  = '';

        // Коментар на цьому ж рядку після ";;;"
        if (str_starts_with($rest, ';;;')) {
            $comment = trim(substr($rest, 3));
            $rest    = '';
        }

        // Якщо рядок даних порожній — шукаємо наступний рядок
        if ($rest === '') {
            while ($i < $n) {
                $nxt = rtrim($lines[$i]);
                if ($nxt === '') { $i++; continue; }
                // Новий запис з номером — не чіпаємо
                if (preg_match('/^\s{0,4}\d+[\s;]/', $nxt)) break;
                // Ще один коментар ";;;"
                if (preg_match('/^\s+;;;\s*(.*)$/', $nxt, $cm)) {
                    if ($comment === '') $comment = trim($cm[1]);
                    $i++; continue;
                }
                // Рядок з даними
                $rest = ltrim($nxt);
                $i++;
                break;
            }
        }

        if ($rest === '') continue;

        // Знаходимо IP/CIDR як якір — все ліворуч = назва списку
        if (preg_match('/^(.*?)\s{2,}(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:\/\d{1,2})?)\s*(.*)$/', $rest, $pm)) {
            $listName = trim($pm[1]);
            $address  = trim($pm[2]);
            $tail     = trim($pm[3]);
        } elseif (preg_match('/^(.*?)\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:\/\d{1,2})?)\s*(.*)$/', $rest, $pm)) {
            $listName = trim($pm[1]);
            $address  = trim($pm[2]);
            $tail     = trim($pm[3]);
        } else {
            continue;
        }

        if ($address === '') continue;

        // Дата і таймаут
        $created = '';
        $timeout = '';
        if ($tail !== '' && preg_match('/^(' . $dateRe . ')\s*(.*)$/', $tail, $dtm)) {
            $created = $dtm[1];
            $timeout = trim($dtm[2]);
        } elseif ($tail !== '') {
            $timeout = $tail;
        }

        $entries[] = [
            'id'       => $id,
            'list'     => $listName,
            'address'  => $address,
            'disabled' => $disabled,
            'dynamic'  => $dynamic,
            'created'  => $created,
            'timeout'  => $timeout,
            'comment'  => $comment,
        ];
    }
    return $entries;
}
?>
<!DOCTYPE html>
<html lang="uk">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Address List — LogPortal</title>
<link rel="stylesheet" href="css/style.css">
<script>(function(){var t=localStorage.getItem('lp_theme');if(t)document.documentElement.setAttribute('data-theme',t);})();</script>
</head>
<body>
<div class="page-wrap">

<?php renderGovStrip(); renderHeader($user); renderNav($user, 'addrlist', $sid); ?>

<div class="breadcrumbs"><div class="container">
  <a href="servers.php">Сервери</a><span class="bc-sep">›</span>
  <?php if ($srv): ?>
    <a href="address_list.php?sid=<?= $sid ?>"><?= htmlspecialchars($srv['name']) ?></a><span class="bc-sep">›</span>
  <?php endif; ?>
  <span class="bc-current">Address List</span>
</div></div>

<main class="page-content"><div class="container">

<div class="page-title-block">
  <div class="page-title-text">
    <h1>📋 MikroTik Address List</h1>
    <div style="margin-top:4px;font-size:.82rem;color:var(--gray-mid)">Управління списками IP адрес Firewall</div>
  </div>
</div>

<!-- ── Вибір сервера ── -->
<div class="srv-select" style="margin-bottom:20px">
  <label style="font-size:.82rem;color:var(--gray-mid);font-weight:600">🔶 MikroTik сервер:</label>
  <select id="srvSelect" onchange="selectServer(this.value)">
    <option value="">— Оберіть сервер —</option>
    <?php foreach ($servers as $s): ?>
    <option value="<?= $s['id'] ?>" <?= $sid == $s['id'] ? 'selected' : '' ?>>
      <?= htmlspecialchars($s['name']) ?> (<?= htmlspecialchars($s['host']) ?>)
    </option>
    <?php endforeach; ?>
  </select>
  <?php if ($sid): ?>
  <button class="tg-btn" onclick="loadLists()" id="btnLoad">⟳ Завантажити</button>
  <?php endif; ?>
</div>

<?php if (!$servers): ?>
<div class="alert alert-warning">
  <span class="alert-icon">⚠</span>
  Немає підключених MikroTik серверів. <a href="server_add.php">Додати сервер</a>
</div>
<?php elseif (!$sid): ?>
<div class="card" style="padding:40px;text-align:center;color:var(--gray-mid)">
  <div style="font-size:2.5rem;margin-bottom:12px">🔶</div>
  <div style="font-size:.9rem">Оберіть MikroTik сервер зі списку вище</div>
</div>
<?php else: ?>

<!-- ── Алерт ── -->
<div id="alertBox" style="display:none"></div>

<!-- ── Додати IP ── -->
<div class="card mb-4" id="addBlock">
  <div class="card-header">
    <div class="card-header-title"><div class="section-head-icon">➕</div> Додати IP до списку</div>
  </div>
  <div class="card-body">
    <div style="display:grid;grid-template-columns:200px 200px 160px 1fr auto;gap:12px;align-items:end" class="add-form-grid">
      <div>
        <label class="form-label">Список (Address List)</label>
        <div style="display:flex;gap:6px">
          <select id="addList" style="flex:1;padding:8px 10px;border:1px solid var(--gray-border);border-radius:6px;font-size:.83rem;background:var(--white);color:var(--gray-text)">
            <option value="">— завантажується —</option>
          </select>
        </div>
        <div style="margin-top:6px;display:flex;align-items:center;gap:6px">
          <input type="text" id="newListName" placeholder="або новий список..."
            style="flex:1;padding:6px 10px;border:1px solid var(--gray-border);border-radius:6px;font-size:.8rem;background:var(--white);color:var(--gray-text)">
        </div>
      </div>
      <div>
        <label class="form-label">IP адреса / підмережа</label>
        <input type="text" id="addAddress" placeholder="192.168.1.1 або 10.0.0.0/24"
          style="width:100%;padding:8px 10px;border:1px solid var(--gray-border);border-radius:6px;font-size:.83rem;box-sizing:border-box;background:var(--white);color:var(--gray-text)">
      </div>
      <div>
        <label class="form-label">Тип запису</label>
        <select id="addType" onchange="toggleTimeout(this.value)"
          style="width:100%;padding:8px 10px;border:1px solid var(--gray-border);border-radius:6px;font-size:.83rem;background:var(--white);color:var(--gray-text)">
          <option value="static">🔒 static (постійний)</option>
          <option value="dynamic">⏱ dynamic (з таймаутом)</option>
        </select>
        <div id="timeoutWrap" style="margin-top:6px;display:none">
          <input type="text" id="addTimeout" value="10d 00:00:00" placeholder="10d 00:00:00"
            style="width:100%;padding:6px 10px;border:1px solid var(--gray-border);border-radius:6px;font-size:.8rem;box-sizing:border-box;background:var(--white);color:var(--gray-text)"
            title="Формат: 10d 00:00:00 або 1w2d3h або 30m">
        </div>
      </div>
      <div>
        <label class="form-label">Коментар (необов'язково)</label>
        <input type="text" id="addComment" placeholder="Причина блокування..."
          style="width:100%;padding:8px 10px;border:1px solid var(--gray-border);border-radius:6px;font-size:.83rem;box-sizing:border-box;background:var(--white);color:var(--gray-text)">
      </div>
      <div>
        <button class="tg-btn" onclick="addIP()" id="btnAdd" style="padding:9px 20px">
          ➕ Додати
        </button>
      </div>
    </div>
  </div>
</div>

<!-- ── Фільтр по списках ── -->
<div class="card mb-4">
  <div class="card-header" style="display:flex;align-items:center;gap:12px;flex-wrap:wrap">
    <div class="card-header-title" style="flex:1"><div class="section-head-icon">📋</div> Записи Address List</div>
    <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">
      <input type="text" id="searchInput" placeholder="🔍 Пошук IP або списку..."
        oninput="filterTable()"
        style="padding:6px 12px;border:1px solid var(--gray-border);border-radius:6px;font-size:.8rem;width:220px;background:var(--white);color:var(--gray-text)">
      <select id="filterList" onchange="filterTable()"
        style="padding:6px 10px;border:1px solid var(--gray-border);border-radius:6px;font-size:.8rem;background:var(--white);color:var(--gray-text)">
        <option value="">Всі списки</option>
      </select>
      <span id="entryCount" style="font-size:.78rem;color:var(--gray-mid)"></span>
    </div>
  </div>
  <div class="card-body" style="padding:0">
    <div id="tableWrap" style="overflow-x:auto;max-height:calc(100vh - 400px);overflow-y:auto">
      <div style="padding:40px;text-align:center;color:var(--gray-mid);font-size:.85rem" id="tableLoader">
        Натисніть «Завантажити» для отримання списку
      </div>
    </div>
  </div>
</div>

<?php endif; ?>
</div></main>

<?php renderFooter(); ?>
</div>

<!-- ── Confirm Modal ── -->
<div class="mini-modal" id="confirmModal">
  <div class="mini-modal-box">
    <div class="mini-modal-title">🗑 Видалити запис?</div>
    <div id="confirmText" style="font-size:.85rem;color:var(--gray-text);margin-bottom:8px"></div>
    <div id="confirmWarn" style="display:none;font-size:.78rem;background:#fff8e1;border:1px solid #ffe082;color:#7c5a00;padding:7px 10px;border-radius:5px;margin-bottom:8px">
      ⚠ Dynamic запис — створений автоматично правилом firewall. RouterOS може відновити його.
    </div>
    <div style="font-size:.78rem;color:var(--gray-mid)">Ця дія незворотня — запис буде видалено з RouterOS</div>
    <div class="mini-modal-footer">
      <button class="btn btn-outline btn-sm" onclick="closeConfirm()">Скасувати</button>
      <button class="btn btn-sm" id="confirmBtn"
        style="background:var(--red-err);color:#fff;border:none;cursor:pointer">
        🗑 Видалити
      </button>
    </div>
  </div>
</div>

<script>
const SID = <?= $sid ?>;
let allEntries = [];
let listNames  = [];

function selectServer(val) {
    if (val) window.location = 'address_list.php?sid=' + val;
}

function toggleTimeout(val) {
    const wrap = document.getElementById('timeoutWrap');
    if (wrap) wrap.style.display = val === 'dynamic' ? 'block' : 'none';
}

function showAlert(type, msg) {
    const box = document.getElementById('alertBox');
    if (!box) return;
    const colors = {
        success: { bg:'#e8f5e9', border:'#a5d6a7', color:'#1b5e20', icon:'✓' },
        error:   { bg:'#fde8e8', border:'#ef9a9a', color:'#b71c1c', icon:'✕' },
        info:    { bg:'#e3f2fd', border:'#90caf9', color:'#0d47a1', icon:'ℹ' },
    };
    const c = colors[type] || colors.info;
    box.style.cssText = `display:flex;align-items:center;gap:10px;padding:12px 16px;margin-bottom:16px;border-radius:8px;font-size:.85rem;background:${c.bg};border:1px solid ${c.border};color:${c.color}`;
    box.innerHTML = `<span style="font-size:1.1rem">${c.icon}</span><span>${msg}</span>`;
    setTimeout(() => { box.style.display = 'none'; }, 5000);
}

async function loadLists(activeList = '') {
    const btn    = document.getElementById('btnLoad');
    const loader = document.getElementById('tableLoader');
    if (btn)    { btn.disabled = true; btn.textContent = '⏳ Завантаження…'; }
    if (loader) { loader.innerHTML = '<div style="padding:40px;text-align:center"><div class="modal-spinner" style="margin:0 auto 12px"></div><div style="font-size:.82rem;color:var(--gray-mid)">Отримання Address List з RouterOS…</div></div>'; }

    try {
        const fd = new FormData();
        fd.append('action', 'get_lists');
        const r = await fetch('address_list.php?sid=' + SID, { method:'POST', body:fd });
        const d = await r.json();
        if (!d.ok) { showAlert('error', '❌ ' + d.error); renderEmpty(); return; }

        allEntries = d.lists || [];
        buildListNames();
        populateListSelects();

        // Після оновлення — встановлюємо фільтр на активний список
        if (activeList) {
            const flt = document.getElementById('filterList');
            if (flt) flt.value = activeList;
        }

        filterTable(); // рендеримо з урахуванням фільтру
        showAlert('success', activeList
            ? `✓ Оновлено — фільтр: «${activeList}»`
            : `✓ Завантажено ${allEntries.length} записів`);
    } catch(e) {
        showAlert('error', '❌ ' + e.message);
        renderEmpty();
    } finally {
        if (btn) { btn.disabled = false; btn.textContent = '⟳ Завантажити'; }
    }
}

function buildListNames() {
    const s = new Set(allEntries.map(e => e.list));
    listNames = [...s].sort();
}

function populateListSelects() {
    // Select для фільтру
    const flt = document.getElementById('filterList');
    const cur = flt.value;
    flt.innerHTML = '<option value="">Всі списки</option>';
    listNames.forEach(n => {
        const o = document.createElement('option');
        o.value = n; o.textContent = n;
        if (n === cur) o.selected = true;
        flt.appendChild(o);
    });

    // Select для додавання
    const add = document.getElementById('addList');
    if (add) {
        const cv = add.value;
        add.innerHTML = '<option value="">— оберіть існуючий —</option>';
        listNames.forEach(n => {
            const o = document.createElement('option');
            o.value = n; o.textContent = n;
            if (n === cv) o.selected = true;
            add.appendChild(o);
        });
    }
}

function renderEmpty() {
    const w = document.getElementById('tableWrap');
    if (w) w.innerHTML = '<div style="padding:40px;text-align:center;color:var(--gray-mid);font-size:.85rem">Записів не знайдено</div>';
}

function renderTable(entries) {
    if (!entries.length) { renderEmpty(); return; }

    document.getElementById('entryCount').textContent = `${entries.length} записів`;

    // Групуємо по списках для кольорів
    const listColors = {};
    const palette = ['#1565c0','#2e7d32','#6a1b9a','#c62828','#e65100','#00695c','#37474f','#ad1457'];
    listNames.forEach((n, i) => listColors[n] = palette[i % palette.length]);

    let html = `<table class="tbl" id="addrTable">
    <thead><tr>
      <th style="width:40px">#</th>
      <th>Список</th>
      <th>IP / Підмережа</th>
      <th>Статус</th>
      <th>Коментар</th>
      <th>Дата додавання</th>
      <th>Таймаут</th>
      <th style="width:80px;text-align:center">Дія</th>
    </tr></thead><tbody>`;

    entries.forEach((e, idx) => {
        const clr = listColors[e.list] || '#1565c0';
        const statusBadge = e.dynamic
            ? '<span class="badge-svc">dynamic</span>'
            : (e.disabled
                ? '<span style="background:#f5f5f5;color:#999;padding:2px 8px;border-radius:10px;font-size:.72rem;font-weight:700">disabled</span>'
                : '<span class="badge-ok">active</span>');

        html += `<tr data-list="${esc(e.list)}" data-addr="${esc(e.address)}" data-id="${esc(e.id)}">
          <td style="color:var(--gray-mid);font-size:.72rem">${e.id}</td>
          <td><span style="display:inline-block;padding:2px 9px;border-radius:10px;font-size:.75rem;font-weight:700;background:${clr}1a;color:${clr};border:1px solid ${clr}44">${esc(e.list)}</span></td>
          <td style="font-family:var(--font-mono);font-weight:600">${esc(e.address)}</td>
          <td>${statusBadge}</td>
          <td style="font-size:.75rem;color:var(--gray-mid);max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(e.comment)}">${esc(e.comment) || '<span style="color:#ccc">—</span>'}</td>
          <td style="font-size:.75rem;color:var(--gray-mid)">${esc(e.created)}</td>
          <td style="font-size:.75rem;color:var(--orange-warn)">${esc(e.timeout) || '—'}</td>
          <td style="text-align:center">
            <button onclick="confirmRemove('${esc(e.id)}','${esc(e.address)}','${esc(e.list)}',${e.dynamic ? 'true' : 'false'})"
              style="background:#fde8e8;color:#c62828;border:1px solid #f5c6c6;border-radius:5px;padding:3px 10px;cursor:pointer;font-size:.75rem;font-weight:600"
              title="${e.dynamic ? 'Dynamic запис — може не видалитись якщо керується правилом' : 'Видалити'}">
              🗑${e.dynamic ? '<span style="font-size:.6rem;margin-left:2px;opacity:.6">D</span>' : ''}
            </button>
          </td>
        </tr>`;
    });

    html += '</tbody></table>';
    const w = document.getElementById('tableWrap');
    if (w) w.innerHTML = html;
}

function filterTable() {
    const search = document.getElementById('searchInput').value.toLowerCase();
    const listF  = document.getElementById('filterList').value;

    const filtered = allEntries.filter(e => {
        const matchList = !listF || e.list === listF;
        const matchSearch = !search ||
            e.address.toLowerCase().includes(search) ||
            e.list.toLowerCase().includes(search) ||
            (e.comment || '').toLowerCase().includes(search);
        return matchList && matchSearch;
    });

    renderTable(filtered);
    document.getElementById('entryCount').textContent =
        filtered.length === allEntries.length
            ? `${allEntries.length} записів`
            : `${filtered.length} з ${allEntries.length}`;
}

async function addIP() {
    const listSel  = document.getElementById('addList')?.value  || '';
    const listNew  = (document.getElementById('newListName')?.value || '').trim();
    const address  = (document.getElementById('addAddress')?.value  || '').trim();
    const comment  = (document.getElementById('addComment')?.value  || '').trim();
    const type     = document.getElementById('addType')?.value || 'static';
    const timeout  = type === 'dynamic'
        ? (document.getElementById('addTimeout')?.value || '10d 00:00:00').trim()
        : '';

    const list = listNew || listSel;
    if (!list)    { showAlert('error', 'Вкажіть або оберіть назву списку'); return; }
    if (!address) { showAlert('error', 'Введіть IP адресу'); return; }

    const btn = document.getElementById('btnAdd');
    if (btn) { btn.disabled = true; btn.textContent = '⏳…'; }

    try {
        const fd = new FormData();
        fd.append('action',  'add_ip');
        fd.append('list',    list);
        fd.append('address', address);
        fd.append('comment', comment);
        fd.append('timeout', timeout);

        const r = await fetch('address_list.php?sid=' + SID, { method:'POST', body:fd });
        const d = await r.json();

        if (!d.ok) {
            showAlert('error', '❌ ' + d.error);
        } else {
            showAlert('success', '✓ ' + d.message);
            if (document.getElementById('addAddress'))  document.getElementById('addAddress').value  = '';
            if (document.getElementById('addComment'))  document.getElementById('addComment').value  = '';
            if (document.getElementById('newListName')) document.getElementById('newListName').value = '';
            await loadLists(list);
        }
    } catch(e) {
        showAlert('error', '❌ ' + e.message);
    } finally {
        if (btn) { btn.disabled = false; btn.textContent = '➕ Додати'; }
    }
}

// ── Confirm видалення ──
let _removeId = '', _removeAddr = '', _removeList = '';

function confirmRemove(id, addr, list, isDynamic) {
    _removeId = id; _removeAddr = addr; _removeList = list;
    document.getElementById('confirmText').innerHTML =
        `IP <b style="font-family:var(--font-mono)">${esc(addr)}</b> зі списку <b>${esc(list)}</b>`;
    const warn = document.getElementById('confirmWarn');
    if (warn) {
        warn.style.display = isDynamic ? 'block' : 'none';
    }
    document.getElementById('confirmModal').classList.add('open');
    document.getElementById('confirmBtn').onclick = doRemove;
}

function closeConfirm() {
    document.getElementById('confirmModal').classList.remove('open');
}

async function doRemove() {
    closeConfirm();
    const fd = new FormData();
    fd.append('action',   'remove_ip');
    fd.append('entry_id', _removeId);
    fd.append('address',  _removeAddr);
    fd.append('list',     _removeList);

    try {
        const r = await fetch('address_list.php?sid=' + SID, { method:'POST', body:fd });
        const d = await r.json();
        if (!d.ok) {
            showAlert('error', '❌ ' + d.error);
        } else {
            showAlert('success', '✓ ' + d.message);
            await loadLists(_removeList);
        }
    } catch(e) {
        showAlert('error', '❌ ' + e.message);
    }
}

function esc(s) {
    return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}

// Закриття confirm по кліку за межами
document.getElementById('confirmModal')?.addEventListener('click', function(e) {
    if (e.target === this) closeConfirm();
});

// Авто-завантаження якщо сервер вже вибрано
<?php if ($sid): ?>
document.addEventListener('DOMContentLoaded', () => loadLists());
<?php endif; ?>

// Enter у полі IP
document.getElementById('addAddress')?.addEventListener('keydown', e => { if (e.key === 'Enter') addIP(); });
</script>
</body>
</html>
