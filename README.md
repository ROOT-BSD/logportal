# LogPortal v2.1.0

Веб-портал моніторингу та аналізу серверних журналів з SSH-підключенням.
Дизайн виконано у стилі офіційного порталу **gov.ua** (НКРЕКП).

---

## Можливості

### 🔐 Авторизація та безпека
- Вхід / реєстрація з валідацією
- Ролі користувачів: `admin` / `user`
- Примусова зміна пароля при першому вході (адмін)
- Сесії: httponly cookie, server-side таймаут 1 год
- HTTP security headers: CSP, X-Frame-Options, X-Content-Type-Options, HSTS, Referrer-Policy
- Темна тема — перемикач, зберігається в localStorage

### 🖥 Сервери
- Підключення до **Linux** та **MikroTik RouterOS** серверів
- Методи автентифікації: пароль, SSH-ключ (RSA/Ed25519/ECDSA) + passphrase
- Прогрес-модал підключення з SSE (Server-Sent Events)
- Автовизначення **Gateway** через SSH (`ip route` / `route -n` / `netstat`)
- Статус online/offline з часом останньої перевірки
- Відображення типу пристрою: 🐧 Linux / 🔶 MikroTik

### 📋 Вибір лог-файлів
- Сканування файлів на сервері через SSH
- Групування по директоріях, розмір файлів
- Фільтрація по даті (від/до)
- Підтримка стиснених файлів `.gz`
- Іконки за типом: Nginx 🟢, Postfix ✉, BIND 🌐, MikroTik 🔶

### 📊 Аналіз логів

#### Nginx (combined format)
- Розподіл HTTP статусів: 2xx / 3xx / 4xx / 5xx
- Топ IP-адреси, URL, User-Agents, реферери
- Трафік по IP (bytes sent)
- Погодинна та денна активність
- Детальна таблиця помилок 4xx/5xx

#### Postfix
- Статистика: sent / deferred / bounced / expired
- Топ відправники та отримувачі
- Час доставки, розміри листів
- Декодування теми MIME (включно з `docflow:` prefix)
- Пошук листів з фільтрами (from/to/date/status)

#### BIND9
- Статистика DNS запитів по типах (A, AAAA, MX, TXT...)
- Топ клієнти та домени
- Виявлення аномалій: ANY-запити (DDoS amplification), NXDOMAIN, REFUSED
- DNS-сканери (>50 різних доменів з одного IP)
- Підтримка форматів: query log, syslog named, security log

#### MikroTik RouterOS
- Аналіз firewall правил (drop/accept статистика)
- VPN сесії: PPPoE, L2TP, OVPN — з тривалістю та IP
- DHCP leases
- Збереження VPN сесій в БД для хронології

### 🛡 Дашборд загроз
- **SSH компрометація** — IP з невдалими входами + подальшим успішним входом
- **SSH Brute-force** — топ атакуючих IP з кількістю спроб
- **SSH вдалі входи** — хронологія успішних автентифікацій
- **HTTP SQLi** — детектор SQL-ін'єкцій в URL/параметрах
- **HTTP XSS** — детектор XSS payload в запитах
- **HTTP Path Traversal** — детектор `../` атак
- **HTTP сканери** — автоматизовані сканери вразливостей
- **SMTP AUTH Brute-force** — атаки на поштовий сервер
- Вибір файлів для аналізу (HTTP logs + mail logs окремо)
- **Email HTML-звіт** — відправка повного звіту загроз на пошту

### 📬 Пошук листів Postfix
- Пошук по: відправнику, отримувачу, темі, Message-ID
- Фільтр по статусу: sent / deferred / bounced / expired
- Фільтр по даті
- Деталі кожного листа: relay, delay, причина відмови/затримки
- Сортування по всіх колонках
- Detail-panel з повною інформацією

### 🌐 VPN сесії MikroTik
- Перегляд активних та завершених VPN сесій
- Протоколи: PPPoE, L2TP, SSTP, OVPN, PPTP
- Хронологія: час підключення, відключення, тривалість
- Статистика по користувачах та IP
- Погодинний та денний графік активності
- Експорт CSV
- Email-звіт

### 📋 MikroTik Address List
- Перегляд всіх IP-списків Firewall RouterOS
- Фільтрація по назві списку, пошук по IP та коментарю
- Додавання IP/CIDR:
  - **static** — постійний запис
  - **dynamic** — з таймаутом (за замовчуванням `10d 00:00:00`)
- Видалення записів (включно з dynamic)
- Підтримка назв списків з пробілами (`port scanners`)
- Підтримка коментарів `;;;` з RouterOS
- Підтримка обох форматів дати: `mar/18/2026` та `2026-03-18`
- Після операції — автооновлення з активним фільтром

### ⚙ Адміністрування
- Управління користувачами (створення, зміна ролі/пароля, видалення)
- Перегляд та видалення серверів
- Визначення Gateway для серверів через SSH (AJAX, без перезавантаження)
- Налаштування SMTP для email-звітів
- Назва організації (відображається в шапці)
- Очищення сесій аналізу

---

## Технологічний стек

| Компонент | Версія | Призначення |
|---|---|---|
| PHP | 8.2+ | Backend |
| SQLite | 3.x | База даних |
| ext-ssh2 | 1.3+ | SSH-підключення (primary) |
| sshpass | 1.09+ | SSH fallback |
| HTML5/CSS3 | — | Інтерфейс |
| JavaScript | ES2020 | AJAX, SSE, UI |

---

## Структура проєкту

```
logportal/
├── index.php              # Авторизація + примусова зміна пароля
├── servers.php            # Список серверів + Connection Modal (SSE)
├── server_add.php         # Додавання / редагування сервера
├── logs.php               # Вибір лог-файлів
├── analyze.php            # Аналіз: Nginx / Postfix / BIND / MikroTik
├── threats.php            # Дашборд загроз + email HTML-звіт
├── mail_search.php        # Пошук листів Postfix
├── vpn.php                # VPN сесії MikroTik + CSV/email
├── address_list.php       # MikroTik Firewall Address List
├── admin.php              # Адмін-панель
├── api.php                # AJAX / SSE endpoint
├── logout.php             # Вихід із системи
├── config.example.php     # Шаблон конфігурації
├── setup.sh               # Скрипт розгортання
├── fix_permissions.sh     # Виправлення прав файлів
│
├── css/
│   └── style.css          # Єдиний файл стилів (темна/світла тема)
│
├── includes/
│   ├── db.php             # SQLite, AES-256-CBC encrypt/decrypt, міграції
│   ├── auth.php           # Сесії, login, реєстрація, force_password_change
│   ├── layout.php         # renderGovStrip/Header/Nav/Footer, sendSecurityHeaders
│   ├── ssh.php            # sshConnect, sshExec, sshExecMikrotik, detectGateway
│   ├── nginx_parser.php   # parseNginxLog, fmtBytes, statusBadge
│   ├── postfix_parser.php # parsePostfixLog, _pfDecodeSubject, detectLogType
│   ├── bind_parser.php    # parseBindLog
│   ├── mikrotik_parser.php# parseMikrotikLog
│   └── filters.php        # filterByDate
│
├── data/                  # SQLite БД (auto-created, захищена .htaccess)
└── uploads/keys/          # SSH ключі користувачів (chmod 600, .htaccess)
```

---

## Встановлення

### Вимоги
```bash
sudo apt install php8.2 php8.2-sqlite3 php8.2-mbstring php8.2-openssl
sudo apt install php8.2-ssh2   # або: sudo pecl install ssh2
sudo apt install sshpass        # fallback для SSH
```

### Кроки
```bash
# 1. Розпакувати
unzip LogPortal_v2.1.0.zip -d /var/www/html/logportal
cd /var/www/html/logportal

# 2. Налаштування (генерує унікальний ENCRYPT_KEY)
chmod +x setup.sh && sudo ./setup.sh

# 3. Права
sudo chown -R www-data:www-data .
```

### Apache конфіг
```apache
<VirtualHost *:443>
    DocumentRoot /var/www/html/logportal
    <Directory /var/www/html/logportal>
        AllowOverride All
        Require all granted
    </Directory>
</VirtualHost>
```

### Nginx конфіг
```nginx
server {
    listen 443 ssl;
    root /var/www/html/logportal;
    index index.php;
    location ~ \.php$ {
        fastcgi_pass unix:/run/php/php8.2-fpm.sock;
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME $realpath_root$fastcgi_script_name;
    }
    location ~ ^/(data|uploads/keys|config\.php) { deny all; }
}
```

---

## Конфігурація

Скопіюйте `config.example.php` → `config.php` і встановіть:

```php
define('ENCRYPT_KEY', 'ВАШ_УНІКАЛЬНИЙ_32_СИМВОЛИ'); // AES-256-CBC ключ
define('APP_TIMEZONE', 'Europe/Kyiv');
```

> `config.php` не включається в Git (`.gitignore`).  
> `setup.sh` генерує його автоматично з унікальним ключем.

---

## Схема БД

| Таблиця | Призначення |
|---|---|
| `users` | Користувачі (id, username, password, role, force_password_change) |
| `servers` | Сервери (host, port, ssh_user, auth_type, device_type, gateway) |
| `settings` | Налаштування SMTP, org_name |
| `log_sessions` | Історія аналізів |
| `vpn_sessions` | VPN сесії MikroTik |

---

## Безпека

| Аспект | Реалізація |
|---|---|
| Паролі SSH | AES-256-CBC шифрування в SQLite |
| SSH ключі | chmod 0600, поза public root |
| SQLite БД | Поза public root, .htaccess deny |
| Сесії | httponly cookie, 1 год таймаут |
| SQL | PDO Prepared Statements |
| XSS | htmlspecialchars() + CSP header |
| Clickjacking | X-Frame-Options: DENY |
| MIME sniff | X-Content-Type-Options: nosniff |
| API | Allowlist для параметра action |

---

## Дані за замовчуванням

```
Логін:  admin
Пароль: admin123
```

> ⚠️ При першому вході система примусово вимагає зміну пароля!

---

## Changelog

### v2.1.0 (14.04.2026)
- Заморожена стабільна версія
- Підняття версії з 2.0.1

### v2.0.1 (18.03.2026)
- MikroTik Address List — управління Firewall IP-списками
- Gateway автовизначення через SSH
- Примусова зміна пароля при першому вході
- Security headers: CSP, X-Frame-Options, HSTS та інші
- Allowlist валідація api.php action параметру
- Декодування теми `docflow:` в листах Postfix
- Єдиний `css/style.css` для всіх сторінок
- Email HTML-звіти загроз

### v2.0.0 (10.03.2026)
- Дашборд загроз із file picker
- BIND9 парсер
- MikroTik VPN сесії в БД
- Темна тема
