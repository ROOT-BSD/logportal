<?php
/* LogPortal — bind_parser.php
   Парсер BIND9 named query log / syslog
   Формати:
   1. Query log:   06-Mar-2026 12:34:56.789 queries: info: client @0x... 1.2.3.4#1234 (example.com): query: example.com IN A + (5.6.7.8)
   2. Syslog:      Mar  6 12:34:56 ns1 named[1234]: client 1.2.3.4#5678: query: example.com IN A + (5.6.7.8)
   3. Named log:   06-Mar-2026 12:34:56.789 client @0x... 1.2.3.4#1234: query: example.com IN A + (5.6.7.8)
*/

// Формат 1: BIND9 власний формат дати
define('BIND_RE1', '/^(\d{2}-\w{3}-\d{4}\s+\d{2}:\d{2}:\d{2}\.\d+)\s+(?:queries:\s+\w+:\s+)?client\s+(?:@\S+\s+)?(\d{1,3}(?:\.\d{1,3}){3}|\[[\da-f:]+\])#(\d+)(?:\s+\([^)]+\))?:\s+query:\s+(\S+)\s+(\w+)\s+(\w+)\s+([+\-\\\\][\w+\-\\\\]*)\s*(?:\(([^)]+)\))?/');
// Формат 2: syslog з named
define('BIND_RE2', '/^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\S+\s+named\[\d+\]:\s+client\s+(?:@\S+\s+)?(\d{1,3}(?:\.\d{1,3}){3}|\[[\da-f:]+\])#(\d+)(?:\s+\([^)]+\))?:\s+query:\s+(\S+)\s+(\w+)\s+(\w+)\s+([+\-\\\\][\w+\-\\\\]*)/');
// Формат 3: security.log — "dd-Mon-yyyy hh:mm:ss.mmm client @0x... IP#port (dom): query (cache) 'dom/TYPE/CLASS' action"
define('BIND_SEC_RE', "/^(\\d{2}-\\w{3}-\\d{4}\\s+\\d{2}:\\d{2}:\\d{2}\\.\\d+)\\s+client\\s+(?:@\\S+\\s+)?(\\d{1,3}(?:\\.\\d{1,3}){3}|\\[[\\da-f:]+\\])#(\\d+)\\s+\\([^)]+\\):\\s+query\\s+\\((\\w+)\\)\\s+'([^']+)\\/(\\w+)\\/(\\w+)'\\s+(\\w+)/");
// Групи: 1=time 2=ip 3=port 4=cache_type 5=qname 6=qtype 7=qclass 8=action

function parseBindLog(string $content, int $limit = 5000000): array
{
    static $months = ['Jan'=>1,'Feb'=>2,'Mar'=>3,'Apr'=>4,'May'=>5,'Jun'=>6,
                      'Jul'=>7,'Aug'=>8,'Sep'=>9,'Oct'=>10,'Nov'=>11,'Dec'=>12];
    static $bindMonths = ['Jan'=>1,'Feb'=>2,'Mar'=>3,'Apr'=>4,'May'=>5,'Jun'=>6,
                          'Jul'=>7,'Aug'=>8,'Sep'=>9,'Oct'=>10,'Nov'=>11,'Dec'=>12];

    $total      = 0;
    $parseErr   = 0;
    $tsStart    = PHP_INT_MAX;
    $tsEnd      = 0;
    $hourCnt    = array_fill(0, 24, 0);
    $dayCnt     = [];

    // Статистика запитів
    $queryTypes  = [];   // A, AAAA, MX, NS, TXT, CNAME, SOA, PTR...
    $queryClass  = [];   // IN, CH, ANY
    $topDomains  = [];   // top queried domains
    $topClients  = [];   // top client IPs
    $topTLDs     = [];   // top TLDs
    $flags       = [];   // +, -, +E, +D, +T тощо

    // Відповіді / коди
    $rcodes      = [];   // NOERROR, NXDOMAIN, SERVFAIL, REFUSED, FORMERR
    $nxdomains   = [];   // топ NXDOMAIN
    $refused     = [];   // топ REFUSED клієнти
    $servfail    = [];   // топ SERVFAIL домени

    // Аномалії
    $anyQueries  = [];   // ANY queries (DDoS amplification)
    $ptrQueries  = 0;    // reverse DNS lookups
    $extClients  = [];   // клієнти поза локальними мережами

    // Детектор сканерів
    $scanners    = [];   // IP що запитують багато різних доменів
    $clientDomains = []; // ip => set of domains (для виявлення сканерів)

    $offset = 0;
    $len    = strlen($content);
    $n      = 0;
    $year   = (int)date('Y');

    while ($offset < $len && $n < $limit) {
        $nl   = strpos($content, "\n", $offset);
        $line = $nl === false ? substr($content, $offset) : substr($content, $offset, $nl - $offset);
        $offset = $nl === false ? $len : $nl + 1;
        $line = rtrim($line, "\r");
        if ($line === '') continue;
        $n++;

        $ts = 0; $clientIp = ''; $port = 0;
        $qname = ''; $qclass = ''; $qtype = ''; $flag = '';

        // ── Спроба Формат 1: BIND власний (dd-Mon-yyyy hh:mm:ss.mmm) ──
        if (preg_match(BIND_RE1, $line, $m)) {
            // $m[1]=time $m[2]=ip $m[3]=port $m[4]=qname $m[5]=qclass $m[6]=qtype $m[7]=flags
            $tStr = $m[1]; // "06-Mar-2026 12:34:56.789"
            $dp   = explode(' ', $tStr);
            $date = explode('-', $dp[0]);
            $time = explode(':', explode('.', $dp[1])[0]);
            $ts   = mktime((int)$time[0],(int)$time[1],(int)$time[2],
                           $bindMonths[$date[1]]??1, (int)$date[0], (int)$date[2]);
            $clientIp = $m[2]; $port=$m[3];
            $qname=$m[4]; $qclass=$m[5]; $qtype=$m[6]; $flag=$m[7];

        // ── Спроба Формат 2: syslog (Mon  d hh:mm:ss) ──
        } elseif (preg_match(BIND_RE2, $line, $m)) {
            $tStr = $m[1]; // "Mar  6 12:34:56"
            $tp   = preg_split('/\s+/', trim($tStr));
            $time = explode(':', $tp[2]);
            $ts   = mktime((int)$time[0],(int)$time[1],(int)$time[2],
                           $months[$tp[0]]??1, (int)$tp[1], $year);
            $clientIp = $m[2]; $port=$m[3];
            $qname=$m[4]; $qclass=$m[5]; $qtype=$m[6]; $flag=$m[7];

        // ── Спроба Формат 3: security.log (dd-Mon-yyyy ... query (cache) 'dom/TYPE/CLASS' action) ──
        } elseif (preg_match(BIND_SEC_RE, $line, $m)) {
            $tStr = $m[1];
            $dp   = explode(' ', $tStr);
            $date = explode('-', $dp[0]);
            $time = explode(':', explode('.', $dp[1])[0]);
            $ts   = mktime((int)$time[0],(int)$time[1],(int)$time[2],
                           $bindMonths[$date[1]]??1, (int)$date[0], (int)$date[2]);
            $clientIp = $m[2]; $port = $m[3];
            $qname = $m[5]; $qtype = $m[6]; $qclass = $m[7];
            $action = strtolower($m[8]); // denied / refused / ...
            $flag = '-'; // security log — запити відхилені

            // Рахуємо refused окремо
            if ($action === 'denied' || $action === 'refused') {
                isset($refused[$clientIp]) ? $refused[$clientIp]++ : $refused[$clientIp] = 1;
            }

        // ── Рядки помилок / статусів (не query) ──
        } else {
            // Перевіряємо на REFUSED/NXDOMAIN поза query рядками
            if (preg_match('/client\s+(\d{1,3}(?:\.\d{1,3}){3})#\d+.*?(?:query denied|REFUSED)/', $line, $em)) {
                isset($refused[$em[1]]) ? $refused[$em[1]]++ : $refused[$em[1]] = 1;
            }
            if (str_contains($line, 'named[') || str_contains($line, 'named:')) {
                // Рядок від named але не query — пропускаємо тихо
            } else {
                $parseErr++;
            }
            continue;
        }

        if (!$ts) { $parseErr++; continue; }
        $total++;

        // ── Час ──
        if ($ts < $tsStart) $tsStart = $ts;
        if ($ts > $tsEnd)   $tsEnd   = $ts;
        $h  = (int)date('H', $ts);
        $dk = date('Y-m-d', $ts);
        $hourCnt[$h]++;
        isset($dayCnt[$dk]) ? $dayCnt[$dk]++ : $dayCnt[$dk] = 1;

        // ── Клієнт ──
        isset($topClients[$clientIp]) ? $topClients[$clientIp]++ : $topClients[$clientIp] = 1;

        // ── Тип запиту ──
        $qtype = strtoupper($qtype);
        isset($queryTypes[$qtype]) ? $queryTypes[$qtype]++ : $queryTypes[$qtype] = 1;

        // ── Клас ──
        $qclass = strtoupper($qclass);
        isset($queryClass[$qclass]) ? $queryClass[$qclass]++ : $queryClass[$qclass] = 1;

        // ── Флаги ──
        $flagClean = preg_replace('/[^+\-EDT0]/', '', $flag ?: '+');
        isset($flags[$flagClean]) ? $flags[$flagClean]++ : $flags[$flagClean] = 1;

        // ── Домен ──
        $qname = rtrim(strtolower($qname), '.');
        isset($topDomains[$qname]) ? $topDomains[$qname]++ : $topDomains[$qname] = 1;

        // TLD
        $parts = explode('.', $qname);
        if (count($parts) >= 2) {
            $tld = end($parts);
            isset($topTLDs[$tld]) ? $topTLDs[$tld]++ : $topTLDs[$tld] = 1;
        }

        // PTR queries (in-addr.arpa, ip6.arpa)
        if (str_ends_with($qname, '.arpa') || $qname === 'arpa') {
            $ptrQueries++;
        }

        // ANY queries — потенційне DDoS amplification
        if ($qtype === 'ANY') {
            isset($anyQueries[$clientIp]) ? $anyQueries[$clientIp]++ : $anyQueries[$clientIp] = 1;
        }

        // NXDOMAIN / REFUSED в flags або rcode
        if (str_contains($line, 'NXDOMAIN')) {
            isset($nxdomains[$qname]) ? $nxdomains[$qname]++ : $nxdomains[$qname] = 1;
        }
        if (str_contains($line, 'REFUSED')) {
            isset($refused[$clientIp]) ? $refused[$clientIp]++ : $refused[$clientIp] = 1;
        }

        // Виявлення сканерів: клієнт що запитує >50 різних доменів
        if (!isset($clientDomains[$clientIp])) $clientDomains[$clientIp] = [];
        if (count($clientDomains[$clientIp]) < 200) {
            $clientDomains[$clientIp][$qname] = 1;
        }
    }

    // ── Виявлення сканерів (>50 різних доменів) ──
    foreach ($clientDomains as $ip => $domains) {
        $cnt = count($domains);
        if ($cnt > 50) $scanners[$ip] = $cnt;
    }

    // ── Сортування ──
    arsort($queryTypes); arsort($queryClass);
    arsort($topDomains); arsort($topClients);
    arsort($topTLDs);    arsort($flags);
    arsort($anyQueries); arsort($nxdomains);
    arsort($refused);    arsort($scanners);
    ksort($dayCnt);

    return [
        'type'          => 'bind',
        'total'         => $total,
        'total_lines'   => $total,
        'parse_errors'  => $parseErr,
        'ts_start'      => $tsStart !== PHP_INT_MAX ? $tsStart : null,
        'ts_end'        => $tsEnd ?: null,
        'hours'         => $hourCnt,
        'days'          => $dayCnt,
        'query_types'   => array_slice($queryTypes,  0, 20, true),
        'query_class'   => $queryClass,
        'top_domains'   => array_slice($topDomains,  0, 25, true),
        'top_clients'   => array_slice($topClients,  0, 25, true),
        'top_tlds'      => array_slice($topTLDs,     0, 20, true),
        'flags'         => $flags,
        'ptr_queries'   => $ptrQueries,
        'any_queries'   => array_slice($anyQueries,  0, 15, true),
        'any_total'     => array_sum($anyQueries),
        'nxdomains'     => array_slice($nxdomains,   0, 15, true),
        'refused'       => array_slice($refused,     0, 15, true),
        'scanners'      => array_slice($scanners,    0, 15, true),
        'unique_clients'=> count($topClients),
        'unique_domains'=> count($topDomains),
    ];
}
