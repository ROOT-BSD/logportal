<?php
/* LogPortal — mikrotik_parser.php
   Підтримувані формати логів Mikrotik:
   1. Syslog (надісланий на external syslog server):
      "2026-03-09 14:23:01 router1 firewall,info input: in:ether1 out:(unknown 0), src-mac ..., proto TCP, 1.2.3.4:12345->192.168.1.1:80, len 60"
   2. Mikrotik local log (export через /log print):
      "mar/09/2026 14:23:01 firewall,info input: ..."
   3. Mikrotik plain syslog (RFC3164):
      "<13>Mar  9 14:23:01 router1 firewall,info input: ..."

   Аналізує:
   - Firewall events (dropped, rejected, accepted)
   - DHCP leases
   - PPPoE / L2TP / SSTP / OVPN sessions
   - Login / logout / auth failures (SSH, WebFig, Winbox, API)
   - Interface events (link up/down)
   - Health / critical events
   - DNS queries (якщо логування включено)
*/

function parseMikrotikLog(string $content, int $limit = 3000000): array
{
    static $months = [
        'jan'=>1,'feb'=>2,'mar'=>3,'apr'=>4,'may'=>5,'jun'=>6,
        'jul'=>7,'aug'=>8,'sep'=>9,'oct'=>10,'nov'=>11,'dec'=>12,
        'Jan'=>1,'Feb'=>2,'Mar'=>3,'Apr'=>4,'May'=>5,'Jun'=>6,
        'Jul'=>7,'Aug'=>8,'Sep'=>9,'Oct'=>10,'Nov'=>11,'Dec'=>12,
    ];

    $total       = 0;
    $parseErr    = 0;
    $tsStart     = PHP_INT_MAX;
    $tsEnd       = 0;
    $hourCnt     = array_fill(0, 24, 0);
    $dayCnt      = [];

    // Firewall
    $fwDropped   = 0;
    $fwRejected  = 0;
    $fwAccepted  = 0;
    $fwLogged    = 0;   // трафік з logging без drop/accept
    $fwByChain   = [];   // input/forward/output
    $fwByProto   = [];
    $fwTopSrc    = [];
    $fwTopDst    = [];
    $fwTopDstPort= [];
    $fwHits      = [];   // останні 50 записів [ts, action, chain, src, dst, proto, dst_port]

    // Auth / Login
    $loginOk     = [];   // user => count
    $loginFail   = [];   // user/ip => count
    $loginFailIp = [];   // ip => count
    $loginSvc    = [];   // ssh/winbox/webfig/api => count

    // VPN / PPP
    $pppSessions = [];   // user => count
    $pppActive   = 0;
    // Детальні сесії для збереження в БД
    // $vpnRaw = [['user','proto','ip','iface','ts_connect','ts_disconnect']]
    $vpnRaw      = [];   // масив подій для post-processing
    $vpnOpen     = [];   // user => ['ts','proto','ip','iface'] — відкриті сесії
    $vpnIpCache  = [];   // user => останній зовнішній IP (щоб connected без logged in мав IP)

    // DHCP
    $dhcpLeases  = [];   // ip => mac (остання)
    $dhcpTotal   = 0;

    // Interface
    $ifEvents    = [];   // iface => [up, down]

    // System / Health
    $sysEvents   = [];
    $critEvents  = [];

    // Topics
    $topics      = [];

    $offset = 0;
    $len    = strlen($content);
    $n      = 0;

    while ($offset < $len && $n < $limit) {
        $nl   = strpos($content, "\n", $offset);
        $line = $nl === false ? substr($content, $offset) : substr($content, $offset, $nl - $offset);
        $offset = ($nl === false) ? $len : $nl + 1;
        $line = rtrim($line, "\r");
        if ($line === '' || $line[0] === '#') continue;
        $n++;

        // ── Парсинг часу ──
        // Прибираємо пробіли/номери рядків на початку (RouterOS /log print)
        $line = ltrim($line);
        $line = preg_replace('/^\d+\s+/', '', $line);
        $ts = 0; $body = $line;

        // Формат 1: "2026-03-09 14:23:01 topic,level ..." (RouterOS 7.x /log print)
        // або    "2026-03-09 14:23:01 hostname topic,level ..." (syslog з hostname)
        // Відрізняємо: якщо 3-тє слово містить кому — це topic (без hostname)
        if (preg_match('/^(\d{4})-(\d{2})-(\d{2})[\sT](\d{2}):(\d{2}):(\d{2})\s+(.+)$/', $line, $m)) {
            $ts   = mktime((int)$m[4],(int)$m[5],(int)$m[6],(int)$m[2],(int)$m[3],(int)$m[1]);
            $rest = $m[7];
            // Якщо перше слово після timestamp НЕ містить кому — це hostname, пропускаємо
            if (preg_match('/^(\S+),/', $rest)) {
                $body = $rest;          // одразу topic,level ...
            } elseif (preg_match('/^\S+\s+(.+)$/', $rest, $rm)) {
                $body = $rm[1];         // hostname + решта
            } else {
                $body = $rest;
            }

        // Формат 2: "mar/09/2026 14:23:01 ..." (RouterOS /log print з роком)
        } elseif (preg_match('/^([a-z]{3})\/(\d{1,2})\/(\d{4})\s+(\d{2}):(\d{2}):(\d{2})\s+(.+)$/i', $line, $m)) {
            $mon  = $months[strtolower($m[1])] ?? 1;
            $ts   = mktime((int)$m[4],(int)$m[5],(int)$m[6],$mon,(int)$m[2],(int)$m[3]);
            $body = $m[7];
            // RouterOS /log print додає джерело: "memory " або "disk " на початку — прибираємо
            $body = preg_replace('/^(memory|disk|echo|remote)\s+/i', '', $body);

        // Формат 3: "mar/09 14:23:01 ..." (RouterOS без року, рік поточний)
        } elseif (preg_match('/^([a-z]{3})\/(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+(.+)$/i', $line, $m)) {
            $mon  = $months[strtolower($m[1])] ?? 1;
            $ts   = mktime((int)$m[3],(int)$m[4],(int)$m[5],$mon,(int)$m[2],(int)date('Y'));
            $body = $m[6];

        // Формат 4: RFC3164 "<PRI>Mon DD HH:MM:SS hostname body" або без PRI
        } elseif (preg_match('/^(?:<\d+>)?([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})(?:\s+\S+)?\s+(.+)$/', $line, $m)) {
            $mon  = $months[$m[1]] ?? 1;
            $yr   = (int)date('Y');
            $ts   = mktime((int)$m[3],(int)$m[4],(int)$m[5],$mon,(int)$m[2],$yr);
            $body = $m[6];

        // Формат 5: тільки час "14:23:01 topic,level message"
        // (RouterOS compact log без дати — берем сьогоднішню дату)
        } elseif (preg_match('/^(\d{2}):(\d{2}):(\d{2})\s+(.+)$/', $line, $m)) {
            $ts   = mktime((int)$m[1],(int)$m[2],(int)$m[3],(int)date('n'),(int)date('j'),(int)date('Y'));
            $body = $m[4];

        // Формат 6: "jan/02 03:04:05" без hostname (варіант з однозначним числом)
        } elseif (preg_match('/^([a-z]{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+(.+)$/i', $line, $m)) {
            $mon  = $months[strtolower($m[1])] ?? 1;
            $ts   = mktime((int)$m[3],(int)$m[4],(int)$m[5],$mon,(int)$m[2],(int)date('Y'));
            $body = $m[6];

        } else {
            $parseErr++;
            continue;
        }

        $total++;
        if ($ts < $tsStart) $tsStart = $ts;
        if ($ts > $tsEnd)   $tsEnd   = $ts;
        $hh = (int)date('H', $ts);
        $hourCnt[$hh]++;
        $dk = date('Y-m-d', $ts);
        isset($dayCnt[$dk]) ? $dayCnt[$dk]++ : $dayCnt[$dk] = 1;

        // ── Визначаємо topic (перше слово перед кому або пробілом) ──
        // Mikrotik body: "firewall,info forward: ..." або "system,info,account ..."
        $topicStr = '';
        if (preg_match('/^([\w,]+)\s/', $body, $tm)) {
            $topicStr = $tm[1];
            $topParts = explode(',', $topicStr);
            foreach ($topParts as $tp) {
                if ($tp && $tp !== 'info' && $tp !== 'warning' && $tp !== 'error' && $tp !== 'critical' && $tp !== 'debug') {
                    isset($topics[$tp]) ? $topics[$tp]++ : $topics[$tp] = 1;
                    break;
                }
            }
        }

        $bodyLow = strtolower($body);

        // ── FIREWALL ──
        if (str_contains($bodyLow, 'firewall') || str_contains($bodyLow, 'forward:') ||
            str_contains($bodyLow, 'input:')   || str_contains($bodyLow, 'output:')) {

            // Визначаємо дію
            // Якщо є назва правила (SSH_CON, DROP_ALL тощо) — визначаємо по ній
            $action = 'logged';
            if (preg_match('/\b(drop|dropped)\b/i', $body))   $action = 'dropped';
            elseif (preg_match('/\breject\b/i', $body))        $action = 'rejected';
            elseif (preg_match('/\baccept\b/i', $body))        $action = 'accepted';
            // Назва правила підказує дію
            elseif (preg_match('/[_-]?(DROP|BLOCK|DENY)[_-]?/i', $body)) $action = 'dropped';
            elseif (preg_match('/[_-]?(ACCEPT|ALLOW|PASS)[_-]?/i', $body)) $action = 'accepted';

            // Ланцюжок
            $chain = 'other';
            if (preg_match('/\b(input|forward|output):/i', $body, $cm)) $chain = strtolower($cm[1]);

            // Протокол
            $proto = '';
            if (preg_match('/proto\s+(\w+)/i', $body, $pm)) $proto = strtoupper($pm[1]);

            // Src IP та dst IP:port
            $srcIp = $dstIp = $dstPort = '';
            // Формат: "1.2.3.4:srcport->5.6.7.8:dstport"
            if (preg_match('/([\d.]+):(\d+)->([\d.]+):(\d+)/', $body, $im)) {
                $srcIp   = $im[1];
                $dstIp   = $im[3];
                $dstPort = (int)$im[4];
            // Або без портів: src-address=1.2.3.4 dst-address=5.6.7.8
            } elseif (preg_match('/src-address=([\d.]+)/i', $body, $sm)) {
                $srcIp = $sm[1];
                preg_match('/dst-address=([\d.]+)/i', $body, $dm) && ($dstIp = $dm[1]);
            // in:iface src-mac xx:xx out:... proto ... 1.2.3.4:p->5.6.7.8:p
            } elseif (preg_match('/\s([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}):(\d+)->([\d.]+):(\d+)/', $body, $im)) {
                $srcIp   = $im[1];
                $dstIp   = $im[3];
                $dstPort = (int)$im[4];
            }

            if ($action === 'dropped')       $fwDropped++;
            elseif ($action === 'rejected')   $fwRejected++;
            elseif ($action === 'accepted')   $fwAccepted++;
            // 'logged' — трафік який логується без явної дії
            else $fwLogged++;

            isset($fwByChain[$chain]) ? $fwByChain[$chain]++ : $fwByChain[$chain] = 1;
            if ($proto) isset($fwByProto[$proto]) ? $fwByProto[$proto]++ : $fwByProto[$proto] = 1;

            if ($srcIp) {
                isset($fwTopSrc[$srcIp]) ? $fwTopSrc[$srcIp]++ : $fwTopSrc[$srcIp] = 1;
            }
            if ($dstIp) {
                isset($fwTopDst[$dstIp]) ? $fwTopDst[$dstIp]++ : $fwTopDst[$dstIp] = 1;
            }
            if ($dstPort) {
                $portKey = $dstPort . '/' . $proto;
                isset($fwTopDstPort[$portKey]) ? $fwTopDstPort[$portKey]++ : $fwTopDstPort[$portKey] = 1;
            }

            if (count($fwHits) < 200) {
                $fwHits[] = [
                    'ts'      => $ts,
                    'action'  => $action,
                    'chain'   => $chain,
                    'src'     => $srcIp,
                    'dst'     => $dstIp,
                    'proto'   => $proto,
                    'dport'   => $dstPort,
                ];
            }
        }

        // ── AUTH / LOGIN ──
        // Виключаємо PPP/VPN рядки — вони містять 'account' або 'logged in' але мають свій блок нижче
        elseif ((str_contains($bodyLow, 'logged in') || str_contains($bodyLow, 'login') ||
                str_contains($bodyLow, 'logged out') || str_contains($bodyLow, 'login failure') ||
                str_contains($bodyLow, 'account')    || str_contains($bodyLow, 'authentication failed'))
            && !str_contains($bodyLow, 'l2tp') && !str_contains($bodyLow, 'ppp,')
            && !str_contains($bodyLow, 'sstp') && !str_contains($bodyLow, 'ovpn')
            && !str_contains($bodyLow, 'pptp') && !str_contains($bodyLow, 'pppoe')
            && !str_contains($bodyLow, 'ipsec')) {

            // Сервіс: ssh, winbox, webfig, api, telnet
            $svc = 'unknown';
            foreach (['ssh','winbox','webfig','api','telnet','console','ftp'] as $sv) {
                if (str_contains($bodyLow, $sv)) { $svc = $sv; break; }
            }

            // Успішний логін: "user NAME logged in from IP via SERVICE"
            // Формат RouterOS: "user mglushak logged in from 172.21.3.254 via l2tp"
            //                  внутрішня IP (assigned) або зовнішня IP — залежить від сервісу
            if (preg_match('/user\s+(\S+)\s+logged\s+in\s+from\s+([\d.a-fA-F:.]+)(?:\s+via\s+(\S+))?/i', $body, $lm)
             || preg_match('/(?:^|\s)(\S+)\s+logged\s+in\s+from\s+([\d.a-fA-F:.]+)(?:\s+via\s+(\S+))?/i', $body, $lm)) {
                $uname = $lm[1];
                $connIp = $lm[2];  // IP з якого підключились
                $svc2  = strtolower($lm[3] ?? $svc);
                // Пропускаємо якщо uname = 'user' (зловили не те)
                if (strtolower($uname) === 'user') {
                    if (preg_match('/user\s+(\S+)\s+logged\s+in\s+from\s+([\d.a-fA-F:.]+)(?:\s+via\s+(\S+))?/i', $body, $lm2)) {
                        $uname = $lm2[1]; $connIp = $lm2[2]; $svc2 = strtolower($lm2[3] ?? $svc);
                    }
                }
                isset($loginOk[$uname]) ? $loginOk[$uname]++ : $loginOk[$uname] = 1;
                isset($loginSvc[$svc2]) ? $loginSvc[$svc2]++ : $loginSvc[$svc2] = 1;

                // Якщо сервіс — VPN протокол → записуємо як VPN сесію
                $vpnProtos = ['l2tp','sstp','ovpn','pptp','pppoe','ipsec','ppp'];
                if (in_array($svc2, $vpnProtos)) {
                    // Відкриваємо VPN сесію (connect)
                    $vpnOpen[$uname] = [
                        'ts'    => $ts,
                        'proto' => $svc2,
                        'ip'    => $connIp,   // зовнішній IP клієнта
                        'iface' => '',
                    ];
                    isset($pppSessions[$uname]) ? $pppSessions[$uname]++ : $pppSessions[$uname] = 1;
                    $pppActive++;
                }
            }
            // Logout — закриваємо VPN сесію якщо відкрита
            elseif (str_contains($bodyLow, 'logged out')) {
                if (preg_match('/user\s+(\S+)\s+logged\s+out/i', $body, $lom)
                 || preg_match('/(\S+)\s+logged\s+out/i', $body, $lom)) {
                    $logoutUser = $lom[1];
                    if (strtolower($logoutUser) === 'user') {
                        if (preg_match('/user\s+(\S+)\s+logged\s+out/i', $body, $lx)) $logoutUser = $lx[1];
                    }
                    if ($logoutUser && !empty($vpnOpen[$logoutUser])) {
                        $open = $vpnOpen[$logoutUser];
                        $vpnRaw[] = [
                            'user'     => $logoutUser,
                            'proto'    => $open['proto'],
                            'ip'       => $open['ip'],
                            'iface'    => $open['iface'],
                            'ts_con'   => $open['ts'],
                            'ts_dis'   => $ts,
                            'duration' => $ts - $open['ts'],
                        ];
                        unset($vpnOpen[$logoutUser]);
                    }
                }
            }
            // Невдалий логін
            elseif (preg_match('/login\s+failure\s+for\s+user\s+(\S+)(?:\s+from\s+([\d.]+))?/i', $body, $fm) ||
                    preg_match('/authentication\s+failed\s+for\s+(\S+)(?:\s+from\s+([\d.]+))?/i', $body, $fm)) {
                $uname = $fm[1]; $ip = $fm[2] ?? 'unknown';
                $key = "$uname@$ip";
                isset($loginFail[$key])    ? $loginFail[$key]++    : $loginFail[$key]    = 1;
                if ($ip !== 'unknown') isset($loginFailIp[$ip]) ? $loginFailIp[$ip]++ : $loginFailIp[$ip] = 1;
            }
        }

        // ── PPP / VPN сесії ──
        // Реальний формат RouterOS:
        //   "l2tp, ppp, info  Moskalenko logged in, 192.168.21.53 from 178.158.198.215"
        //   "l2tp, ppp, info  <l2tp-Moskalenko>: connected"
        //   "l2tp, ppp, info  <l2tp-Moskalenko>: disconnected"
        elseif (str_contains($bodyLow, 'pppoe') || str_contains($bodyLow, 'l2tp') ||
                str_contains($bodyLow, 'sstp')  || str_contains($bodyLow, 'ovpn') ||
                str_contains($bodyLow, 'pptp')  || str_contains($bodyLow, 'ppp,') ||
                str_contains($bodyLow, 'ppp ') || str_contains($bodyLow, 'ipsec')) {

            // Протокол
            $proto = 'ppp';
            foreach (['l2tp','sstp','ovpn','pptp','pppoe','ipsec'] as $pr) {
                if (str_contains($bodyLow, $pr)) { $proto = $pr; break; }
            }

            // Відрізаємо топік: "l2tp, ppp, info, account  Payload" → "Payload"
            // Варіанти: "info  X", "info, account  X", "error  X"
            $payload = preg_replace('/^[\w,\s]+(info|error|warning|debug)(,\s*\w+)?\s+/i', '', $body);
            $payload = ltrim($payload);

            // ── Формат 1: "NAME logged in, INTERNAL_IP from EXTERNAL_IP"
            // Moskalenko logged in, 192.168.21.53 from 178.158.198.215
            if (preg_match('/^(\S+)\s+logged\s+in,\s*([\d.]+)\s+from\s+([\d.]+)/i', $payload, $lm)) {
                $uname  = $lm[1];
                $ipInt  = $lm[2];   // внутрішній (assigned)
                $ipExt  = $lm[3];   // зовнішній (реальний IP клієнта)
                $vpnIpCache[$uname] = $ipExt;  // кешуємо IP на випадок якщо connected прийде окремо
                $vpnOpen[$uname] = ['ts'=>$ts, 'proto'=>$proto, 'ip'=>$ipExt, 'iface'=>'', 'ip_int'=>$ipInt];
                isset($pppSessions[$uname]) ? $pppSessions[$uname]++ : $pppSessions[$uname] = 1;
                $pppActive++;

            // ── Формат 2: "<iface-NAME>: connected" або "disconnected"
            // <l2tp-Moskalenko>: connected
            } elseif (preg_match('/^<([^>]+)>:\s*(connected|disconnected|terminated|timeout)/i', $payload, $im)) {
                $iface    = $im[1];           // l2tp-Moskalenko
                $event    = strtolower($im[2]);
                // Витягуємо ім'я: після першого дефісу (l2tp-Moskalenko → Moskalenko)
                $uname = preg_replace('/^[a-z0-9]+-/i', '', $iface);
                if (!$uname) $uname = $iface;

                if ($event === 'connected') {
                    if (isset($vpnOpen[$uname])) {
                        // logged in вже є — просто оновлюємо iface
                        $vpnOpen[$uname]['iface'] = $iface;
                    } else {
                        // connected без logged in — шукаємо IP в $vpnIpCache (з попередніх рядків)
                        $cachedIp = $vpnIpCache[$uname] ?? '';
                        $vpnOpen[$uname] = ['ts'=>$ts, 'proto'=>$proto, 'ip'=>$cachedIp, 'iface'=>$iface];
                        isset($pppSessions[$uname]) ? $pppSessions[$uname]++ : $pppSessions[$uname] = 1;
                        $pppActive++;
                    }
                } else {
                    // disconnected / terminated / timeout — закриваємо сесію
                    if (isset($vpnOpen[$uname])) {
                        $open = $vpnOpen[$uname];
                        $vpnRaw[] = [
                            'user'     => $uname,
                            'proto'    => $open['proto'],
                            'ip'       => $open['ip'],
                            'iface'    => $iface,
                            'ts_con'   => $open['ts'],
                            'ts_dis'   => $ts,
                            'duration' => $ts - $open['ts'],
                        ];
                        unset($vpnOpen[$uname]);
                    } else {
                        // disconnect без connect — неповна сесія
                        $vpnRaw[] = [
                            'user' => $uname, 'proto' => $proto, 'ip' => '',
                            'iface' => $iface, 'ts_con' => null,
                            'ts_dis' => $ts, 'duration' => null,
                        ];
                    }
                }

            // ── Формат 3: старий — "user NAME logged in from IP via proto"
            } elseif (preg_match('/(?:user\s+)?(\S+)\s+logged\s+in\s+from\s+([\d.a-fA-F:.]+)/i', $payload, $lm)) {
                $uname = $lm[1];
                $ip    = $lm[2];
                if (strtolower($uname) !== 'user') {
                    $vpnOpen[$uname] = ['ts'=>$ts, 'proto'=>$proto, 'ip'=>$ip, 'iface'=>''];
                    isset($pppSessions[$uname]) ? $pppSessions[$uname]++ : $pppSessions[$uname] = 1;
                    $pppActive++;
                }

            // ── Інші рядки: оновлення iface або просто рахуємо
            } else {
                // <iface>: authenticated або інші рядки — ігноруємо
            }

        } // end PPP/VPN block

        // ── DHCP ──
        elseif (str_contains($bodyLow, 'dhcp') || str_contains($bodyLow, 'assigned') ||
                str_contains($bodyLow, 'deassigned')) {

            if (preg_match('/([\d.]+)\s+(?:assigned\s+to|for)\s+([0-9A-Fa-f:]{17})/i', $body, $dh)) {
                $dhcpLeases[$dh[1]] = $dh[2];
                $dhcpTotal++;
            } elseif (str_contains($bodyLow, 'assigned') || str_contains($bodyLow, 'lease')) {
                $dhcpTotal++;
            }
        }

        // ── Interface events ──
        elseif (str_contains($bodyLow, 'link up') || str_contains($bodyLow, 'link down') ||
                str_contains($bodyLow, 'interface')) {

            if (preg_match('/\b([\w\/.-]+)\s+link\s+(up|down)/i', $body, $ie)) {
                $iface = $ie[1];
                $state = strtolower($ie[2]);
                if (!isset($ifEvents[$iface])) $ifEvents[$iface] = ['up'=>0,'down'=>0];
                isset($ifEvents[$iface][$state]) ? $ifEvents[$iface][$state]++ : $ifEvents[$iface][$state] = 1;
            }
        }

        // ── System / Critical ──
        elseif (str_contains($bodyLow, 'system') || str_contains($bodyLow, 'critical') ||
                str_contains($bodyLow, 'rebooted')|| str_contains($bodyLow, 'startup')) {

            if (str_contains($bodyLow, 'critical') || str_contains($bodyLow, 'rebooted') ||
                str_contains($bodyLow, 'power') || str_contains($bodyLow, 'voltage')) {
                $critEvents[] = ['ts'=>$ts, 'msg'=>substr($body, 0, 120)];
            } else {
                $sysEvents[]  = ['ts'=>$ts, 'msg'=>substr($body, 0, 120)];
            }
        }
    }

    // Сортування
    arsort($fwTopSrc);    arsort($fwTopDst);
    arsort($fwTopDstPort);arsort($fwByProto);
    arsort($loginOk);     arsort($loginFail); arsort($loginFailIp);
    arsort($pppSessions); arsort($loginSvc);

    // Незакриті сесії — буфер закінчився, disconnect не був в логах
    // Сесії старші 24 годин вважаються завершеними (disconnect просто не залогований)
    $now24 = time();
    foreach ($vpnOpen as $uname => $open) {
        $age = $open['ts'] ? ($now24 - $open['ts']) : PHP_INT_MAX;
        if ($age > 86400) continue;  // > 24г — не активна, пропускаємо
        $vpnRaw[] = [
            'user'     => $uname,
            'proto'    => $open['proto'],
            'ip'       => $open['ip'],
            'iface'    => $open['iface'],
            'ts_con'   => $open['ts'],
            'ts_dis'   => null,   // дійсно активна (менше 24г)
            'duration' => null,
        ];
    }
    arsort($topics);
    ksort($dayCnt);

    $fwTotal = $fwDropped + $fwRejected + $fwAccepted + $fwLogged;

    return [
        'type'          => 'mikrotik',
        'total_lines'   => $total,
        'parse_errors'  => $parseErr,
        'ts_start'      => $tsStart !== PHP_INT_MAX ? $tsStart : null,
        'ts_end'        => $tsEnd ?: null,
        'hours'         => $hourCnt,
        'days'          => $dayCnt,
        'peak_hour'     => $hourCnt ? array_search(max($hourCnt), $hourCnt) : 0,
        'topics'        => array_slice($topics, 0, 20, true),
        // Firewall
        'fw_total'      => $fwTotal,
        'fw_logged'     => $fwLogged,
        'fw_dropped'    => $fwDropped,
        'fw_rejected'   => $fwRejected,
        'fw_accepted'   => $fwAccepted,
        'fw_by_chain'   => $fwByChain,
        'fw_by_proto'   => array_slice($fwByProto, 0, 15, true),
        'fw_top_src'    => array_slice($fwTopSrc, 0, 20, true),
        'fw_top_dst'    => array_slice($fwTopDst, 0, 15, true),
        'fw_top_ports'  => array_slice($fwTopDstPort, 0, 20, true),
        'fw_hits'       => array_slice($fwHits, -50),
        // Auth
        'login_ok'      => array_slice($loginOk, 0, 15, true),
        'login_fail'    => array_slice($loginFail, 0, 15, true),
        'login_fail_ip' => array_slice($loginFailIp, 0, 15, true),
        'login_svc'     => $loginSvc,
        // VPN/PPP
        'ppp_sessions'  => array_slice($pppSessions, 0, 20, true),
        'ppp_total'     => $pppActive,
        'vpn_sessions'  => $vpnRaw,
        // DHCP
        'dhcp_total'    => $dhcpTotal,
        'dhcp_leases'   => array_slice($dhcpLeases, 0, 30, true),
        // Interfaces
        'if_events'     => $ifEvents,
        // System
        'sys_events'    => array_slice($sysEvents, -20),
        'crit_events'   => array_slice($critEvents, -20),
    ];
}
