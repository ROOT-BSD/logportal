# LogPortal v2.0.1

Портал моніторингу та аналізу логів серверів з SSH-підключенням.  
Дизайн виконано у стилі офіційного порталу **gov.ua** (НКРЕКП).

## Можливості

- 🔐 **Авторизація** — сесії, ролі (admin / user)
- 🖥 **Сервери** — SSH-підключення до Linux / MikroTik, прогрес-модал підключення
- 🌐 **Gateway** — автовизначення IP шлюзу через SSH (ip route / route -n / netstat)
- 📋 **Логи** — перегляд і вибір файлів на сервері, фільтрація по даті
- 📊 **Аналіз** — Nginx, Postfix, BIND9, MikroTik RouterOS
- 🛡 **Загрози** — SSH brute-force, компрометація, HTTP SQLi/XSS/Path Traversal, SMTP AUTH
- 📬 **Пошта** — пошук листів Postfix (sent / deferred / bounced / expired), декодування теми docflow
- 🌐 **VPN** — перегляд PPPoE/L2TP/OVPN сесій MikroTik
- 📋 **Address List** — управління IP-списками Firewall MikroTik (перегляд, додавання, видалення)
- 📧 **Email звіти** — відправка повного HTML-звіту загроз на пошту (SMTP)
- 🌙 **Темна тема** — перемикач, зберігається в localStorage

## Стек

| Технологія | Призначення |
|---|---|
| PHP 8.2+ | Backend (PDO, OpenSSL, ext-ssh2) |
| SQLite 3 | База даних (через PDO) |
| HTML5 / CSS3 | Єдиний файл стилів css/style.css |
| ext-ssh2 / sshpass | SSH-підключення до серверів |

## Структура проєкту

```
logportal/
├── index.php              # Авторизація
├── servers.php            # Список серверів + Connection Modal
├── server_add.php         # Додавання / редагування сервера + визначення gateway
├── logs.php               # Вибір лог-файлів
├── analyze.php            # Аналіз: Nginx / Postfix / BIND / MikroTik
├── threats.php            # Дашборд загроз + email звіт
├── mail_search.php        # Пошук листів Postfix
├── vpn.php                # VPN сесії MikroTik
├── address_list.php       # MikroTik Address List (Firewall)
├── admin.php              # Адмін-панель (користувачі, сервери, SMTP, gateway)
├── api.php                # AJAX / SSE endpoint
├── logout.php             # Вихід
├── setup.sh               # Скрипт розгортання
├── fix_permissions.sh     # Виправлення прав файлів
├── favicon.ico
│
├── css/
│   └── style.css          # Єдиний файл стилів для всіх сторінок
│
├── includes/
│   ├── db.php             # SQLite, encrypt/decrypt, timezone, міграції
│   ├── auth.php           # Сесії, login, ролі
│   ├── layout.php         # renderGovStrip, renderHeader, renderNav, renderFooter
│   ├── ssh.php            # sshConnect, sshExec, sshExecMikrotik, getLogFiles, detectGateway
│   ├── nginx_parser.php   # parseNginxLog, fmtBytes, statusBadge
│   ├── postfix_parser.php # parsePostfixLog, detectLogType, _pfDecodeSubject
│   ├── bind_parser.php    # parseBindLog (BIND9 query/security log)
│   ├── mikrotik_parser.php# parseMikrotikLog (firewall, VPN, DHCP)
│   └── filters.php        # filterByDate (Nginx/Postfix/BIND)
│
├── data/                  # SQLite БД (auto-created)
│   └── .htaccess          # deny from all
└── uploads/keys/          # SSH ключі (chmod 600)
    └── .htaccess          # deny from all
```

## Встановлення

```bash
# 1. Розпакуйте архів
unzip LogPortal_v2.0.1.zip -d /var/www/html/logportal
cd /var/www/html/logportal

# 2. Запустіть setup
chmod +x setup.sh && sudo ./setup.sh

# 3. Права
sudo chown -R www-data:www-data .
sudo chmod +x fix_permissions.sh && sudo ./fix_permissions.sh
```

## Вимоги

```bash
# PHP розширення
sudo apt install php-ssh2 php-sqlite3 php-mbstring php-openssl

# sshpass (fallback якщо немає ext-ssh2)
sudo apt install sshpass
```

## Схема БД

### Таблиця `servers`
| Колонка | Тип | Опис |
|---|---|---|
| id | INTEGER | Primary key |
| user_id | INTEGER | Власник (FK users) |
| name | TEXT | Назва сервера |
| host | TEXT | IP або hostname |
| port | INTEGER | SSH порт (default 22) |
| ssh_user | TEXT | SSH логін |
| auth_type | TEXT | password або key |
| ssh_password | TEXT | Зашифрований пароль (AES-256-CBC) |
| key_path | TEXT | Шлях до SSH ключа |
| key_passphrase | TEXT | Зашифрована парольна фраза |
| description | TEXT | Опис |
| device_type | TEXT | linux або mikrotik |
| gateway | TEXT | IP шлюзу за замовчуванням |
| status | TEXT | online / offline / unknown |
| last_check | DATETIME | Час останньої перевірки |
| created_at | DATETIME | Час створення |

### Таблиця `settings`
| Ключ | Опис |
|---|---|
| smtp_host | SMTP сервер |
| smtp_port | SMTP порт |
| smtp_user | SMTP логін |
| smtp_pass | SMTP пароль (зашифрований) |
| smtp_from | Email відправника |
| alert_to | Email отримувача |
| org_name | Назва організації (відображається в шапці) |

## Підтримувані формати логів

| Тип | Формат |
|---|---|
| **Nginx** | combined: `$remote_addr - ... "$request" $status $bytes` |
| **Postfix** | syslog або `/opt/log/postfix/РРРР/ММ/ДД/` |
| **BIND9** | query log (власний формат), syslog named, security log |
| **MikroTik** | RouterOS syslog (firewall, VPN, DHCP, PPPoE, L2TP) |

## Address List (MikroTik Firewall)

Сторінка `address_list.php` дозволяє:
- Переглядати всі IP-списки Firewall з фільтрацією та пошуком
- Додавати IP/CIDR до списку як **static** (постійний) або **dynamic** (з таймаутом, default 10d)
- Видаляти записи (включно з dynamic)
- Відображає: список, IP, статус, коментар `;;;`, дату, таймаут
- Підтримує назви списків з пробілами (`port scanners`, `my list` тощо)
- Підтримує обидва формати дати RouterOS: `mar/18/2026` та `2026-03-18`

## Gateway Detection

Функція `detectGateway()` в `ssh.php`:
- Виконується через SSH після успішного підключення (тільки Linux)
- Пробує команди: `ip route show default` → `ip route get 8.8.8.8` → `route -n` → `netstat -rn`
- **server_add.php**: чекбокс при додаванні/редагуванні сервера
- **admin.php**: кнопка `⟳ SSH` навпроти кожного Linux-сервера — AJAX без перезавантаження

## Налаштування SMTP

В адмін-панелі (`admin.php` → вкладка Налаштування):

| Параметр | Опис |
|---|---|
| SMTP сервер | Хост поштового сервера |
| Порт | 465 (SSL) / 587 (STARTTLS) / 25 |
| Логін / Пароль | Авторизація SMTP |
| Email відправника | From адреса |
| Email отримувача | Куди надсилати звіти |
| Назва організації | Відображається в шапці та footer |

## Дані за замовчуванням

```
Логін:  admin
Пароль: admin123
```

> ⚠️ Змініть пароль адміністратора одразу після першого входу!

## Безпека

- Паролі SSH — AES-256-CBC шифрування в БД
- SSH-ключі — права 0600, поза public root, .htaccess deny
- SQLite БД — поза public root + .htaccess deny
- Сесії — httponly cookie, таймаут 1 год
- SQL-ін'єкції — PDO Prepared Statements
- `info.php` — відсутній у production збірці

## Changelog

### v2.0.1 (18.03.2026)
- **Address List** — нова сторінка управління MikroTik Firewall IP-списками
  - Перегляд, додавання (static/dynamic з таймаутом), видалення
  - Парсинг RouterOS з підтримкою назв з пробілами, коментарів `;;;`, обох форматів дати
  - Після операцій — автооновлення з фільтром по поточному списку
- **Gateway** — автовизначення IP шлюзу через SSH для Linux серверів
  - Чекбокс при додаванні/редагуванні сервера
  - Кнопка `⟳ SSH` в адмін-панелі для вже підключених серверів
  - Зберігається в БД (колонка `gateway`)
- **Пошта** — декодування теми `docflow:` (показує тільки текст після префіксу)
- **Стилі** — всі inline `<style>` перенесено до єдиного `css/style.css`
- **Email звіт** — повноцінний HTML з таблицями SSH / HTTP / SMTP аналізу
- **BIND9** — файли `named*`, `query*`, `bind*` знаходяться при скануванні
- Видалено `report.html` та `info.php`

### v2.0.0 (10.03.2026)
- Рефакторинг threats.php: file picker для HTTP/mail аналізу
- SSH картки: компрометація, brute-force, вдалі входи
- Темна тема, org_name з БД
- BIND9 парсер та аналіз
- MikroTik VPN сесії в БД
