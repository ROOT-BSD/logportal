#!/bin/bash
# ════════════════════════════════════════
#  LogPortal v2.0.1 — Скрипт розгортання
# ════════════════════════════════════════

set -e
BLUE='\033[1;34m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[OK]${NC}    $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC}  $1"; }
err()  { echo -e "${RED}[ERROR]${NC} $1"; }
info() { echo -e "${BLUE}[INFO]${NC}  $1"; }

echo ""
echo -e "${BLUE}════════════════════════════════════════${NC}"
echo -e "${BLUE}   LogPortal — Встановлення v2.0.1     ${NC}"
echo -e "${BLUE}════════════════════════════════════════${NC}"
echo ""

# ─── PHP ───
if ! command -v php &>/dev/null; then
    err "PHP не встановлено. Встановіть PHP 8.2+"
    echo "    sudo apt install php php-cli php-sqlite3 php-openssl"
    exit 1
fi
PHP_VER=$(php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;')
ok "PHP $PHP_VER знайдено"

# ─── PHP Extensions ───
REQUIRED_EXTS=("pdo_sqlite" "openssl" "json" "fileinfo" "mbstring")
for EXT in "${REQUIRED_EXTS[@]}"; do
    if php -m 2>/dev/null | grep -qi "^${EXT}$"; then
        ok "PHP ext: $EXT"
    else
        warn "PHP ext: $EXT — відсутній"
        echo "    sudo apt install php-${EXT}"
    fi
done

# ─── Optional: PHP ssh2 ───
if php -m 2>/dev/null | grep -qi "^ssh2$"; then
    ok "PHP ext: ssh2 (нативне SSH)"
else
    warn "PHP ext: ssh2 — відсутній (fallback через sshpass)"
    echo "    sudo apt install php-ssh2"
fi

# ─── sshpass ───
if command -v sshpass &>/dev/null; then
    ok "sshpass: $(sshpass -V 2>&1 | head -1)"
else
    warn "sshpass не знайдено"
    echo "    sudo apt install sshpass"
fi

# ─── ssh ───
if command -v ssh &>/dev/null; then
    ok "OpenSSH: $(ssh -V 2>&1)"
else
    warn "ssh не знайдено. sudo apt install openssh-client"
fi

# ─── Директорії ───
echo ""
info "Створення директорій..."
mkdir -p data uploads/keys
chmod 750 data
chmod 700 uploads/keys
ok "Директорії: data/, uploads/keys/"

# ─── .htaccess ───
cat > data/.htaccess <<'EOF'
Order deny,allow
Deny from all
EOF
cat > uploads/keys/.htaccess <<'EOF'
Order deny,allow
Deny from all
EOF
ok "Захист .htaccess створено"

# ─── config.php ───
echo ""
info "Перевірка конфігурації..."
if [ ! -f "config.php" ]; then
    if [ -f "config.example.php" ]; then
        cp config.example.php config.php
        # Генеруємо унікальний ENCRYPT_KEY (32 hex символи = 16 байт)
        NEWKEY=$(php -r "echo bin2hex(random_bytes(16));")
        if [[ "$OSTYPE" == "darwin"* ]]; then
            sed -i '' "s/ЗАМІНІТЬ_НА_32_СИМВОЛИ_СВОГО_КЛЮЧА/${NEWKEY}/" config.php
        else
            sed -i "s/ЗАМІНІТЬ_НА_32_СИМВОЛИ_СВОГО_КЛЮЧА/${NEWKEY}/" config.php
        fi
        ok "config.php створено з унікальним ключем шифрування"
        echo -e "    ${YELLOW}⚠  Збережіть config.php — він не потрапляє в Git!${NC}"
    else
        warn "config.example.php не знайдено — config.php не створено"
        echo "    Ключ шифрування буде дефолтним. НЕ використовуйте в production!"
    fi
else
    ok "config.php вже існує"
fi

# ─── Права на файли ───
find . -name "*.php" -exec chmod 644 {} \;
find . -name "*.sh"  -exec chmod 755 {} \;
chmod 750 data uploads/keys
ok "Права на файли встановлено"

# ─── Ініціалізація БД ───
echo ""
info "Ініціалізація БД..."
php -r "
require 'includes/db.php';
\$db = getDB();
echo 'OK';
" 2>/dev/null && ok "SQLite БД ініціалізовано" || warn "БД буде ініціалізована при першому запиті"

# ─── Підказка Nginx ───
echo ""
info "Для Nginx додайте до конфігурації:"
echo ""
echo -e "    ${BLUE}location ~ ^/(data|uploads/keys|config\\.php) {${NC}"
echo -e "    ${BLUE}    deny all;${NC}"
echo -e "    ${BLUE}}${NC}"

echo ""
echo -e "${GREEN}════════════════════════════════════════${NC}"
echo -e "${GREEN}   Готово!                              ${NC}"
echo -e "${GREEN}════════════════════════════════════════${NC}"
echo ""
echo -e "  Дані для входу за замовчуванням:"
echo -e "  Логін:  ${YELLOW}admin${NC}"
echo -e "  Пароль: ${YELLOW}admin123${NC}"
echo ""
echo -e "  ${RED}⚠  Змініть пароль адміна після першого входу!${NC}"
echo ""
