#!/bin/bash
# ════════════════════════════════════════════════
#  LogPortal — fix_permissions.sh
#  Виправлення прав доступу для Apache/Nginx
#  Запускати від root: sudo bash fix_permissions.sh
# ════════════════════════════════════════════════

set -e

WEBROOT="${1:-/var/www/html}"
WEBUSER="${2:-www-data}"
WEBGROUP="${3:-www-data}"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; BLUE='\033[1;34m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[OK]${NC}    $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC}  $1"; }
info() { echo -e "${BLUE}[INFO]${NC}  $1"; }

echo ""
echo -e "${BLUE}═══════════════════════════════════════════${NC}"
echo -e "${BLUE}   LogPortal — Виправлення прав доступу   ${NC}"
echo -e "${BLUE}═══════════════════════════════════════════${NC}"
echo ""
info "Webroot : $WEBROOT"
info "WebUser : $WEBUSER:$WEBGROUP"
echo ""

# ─── Перевірка root ───
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[ERROR]${NC} Запускайте від root: sudo bash fix_permissions.sh"
    exit 1
fi

# ─── 1. data/ ───
DATA_DIR="$WEBROOT/data"
info "Налаштування data/ ..."
mkdir -p "$DATA_DIR"
chown "$WEBUSER:$WEBGROUP" "$DATA_DIR"
chmod 750 "$DATA_DIR"
# Якщо БД вже існує
if [ -f "$DATA_DIR/logportal.db" ]; then
    chown "$WEBUSER:$WEBGROUP" "$DATA_DIR/logportal.db"
    chmod 640 "$DATA_DIR/logportal.db"
    ok "data/logportal.db — права виправлено"
fi
ok "data/ — chown $WEBUSER:$WEBGROUP, chmod 750"

# ─── 2. uploads/keys/ ───
KEYS_DIR="$WEBROOT/uploads/keys"
info "Налаштування uploads/keys/ ..."
mkdir -p "$KEYS_DIR"
chown -R "$WEBUSER:$WEBGROUP" "$WEBROOT/uploads"
chmod 750 "$WEBROOT/uploads"
chmod 700 "$KEYS_DIR"
ok "uploads/keys/ — chmod 700"

# ─── 3. PHP файли (тільки читання для www-data) ───
info "Налаштування PHP/CSS файлів ..."
find "$WEBROOT" -maxdepth 3 -name "*.php" -exec chmod 644 {} \;
find "$WEBROOT" -maxdepth 3 -name "*.css" -exec chmod 644 {} \;
find "$WEBROOT" -maxdepth 3 -name "*.sh"  -exec chmod 755 {} \;
ok "PHP/CSS файли — chmod 644"

# ─── 4. .htaccess захист ───
info "Створення .htaccess захисту ..."
cat > "$DATA_DIR/.htaccess" <<'EOF'
# Заборона прямого доступу до БД
<FilesMatch ".*">
    Order deny,allow
    Deny from all
</FilesMatch>
EOF
cat > "$KEYS_DIR/.htaccess" <<'EOF'
# Заборона прямого доступу до SSH-ключів
<FilesMatch ".*">
    Order deny,allow
    Deny from all
</FilesMatch>
EOF
ok ".htaccess — захист data/ та uploads/keys/"

# ─── 5. Перевірка SQLite ───
info "Перевірка SQLite..."
if su -s /bin/sh "$WEBUSER" -c "touch '$DATA_DIR/.write_test' 2>/dev/null && rm -f '$DATA_DIR/.write_test'"; then
    ok "SQLite директорія доступна для запису ($WEBUSER)"
else
    warn "Перевірте SELinux/AppArmor якщо проблема залишається:"
    echo "    sudo chcon -Rv --type=httpd_sys_rw_content_t $DATA_DIR"
    echo "    або: sudo setenforce 0  (тимчасово)"
fi

# ─── 6. SELinux підказка ───
if command -v getenforce &>/dev/null && [ "$(getenforce)" = "Enforcing" ]; then
    warn "SELinux активний! Виконайте:"
    echo "    sudo chcon -Rv --type=httpd_sys_rw_content_t $DATA_DIR"
    echo "    sudo chcon -Rv --type=httpd_sys_rw_content_t $KEYS_DIR"
fi

# ─── 7. Docker-специфічні налаштування ───
info "Перевірка Docker контексту..."
if [ -f "/.dockerenv" ]; then
    ok "Docker контейнер виявлено"
    # У Docker часто немає окремого www-data — перевіримо
    if ! id "$WEBUSER" &>/dev/null; then
        warn "Користувач $WEBUSER не знайдений, спробуємо apache"
        WEBUSER="apache"
        chown "$WEBUSER:$WEBUSER" "$DATA_DIR" "$KEYS_DIR" 2>/dev/null || true
    fi
fi

echo ""
echo -e "${GREEN}═══════════════════════════════════════════${NC}"
echo -e "${GREEN}   Права доступу виправлено!               ${NC}"
echo -e "${GREEN}═══════════════════════════════════════════${NC}"
echo ""
echo "  Тепер перезапустіть PHP-FPM або Apache:"
echo -e "  ${BLUE}sudo systemctl restart php8.2-fpm${NC}"
echo -e "  ${BLUE}sudo systemctl restart apache2${NC}"
echo -e "  ${BLUE}або в Docker: supervisorctl restart php-fpm${NC}"
echo ""

# ─── Підсумкова перевірка ───
echo "  Підсумок:"
ls -la "$WEBROOT/data/" 2>/dev/null || true
ls -la "$WEBROOT/uploads/" 2>/dev/null || true
echo ""
