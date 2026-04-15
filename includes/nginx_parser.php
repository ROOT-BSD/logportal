<?php
/* LogPortal — nginx_parser.php */

define('NGINX_RE', '/^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)]\s+"([^"]*?)"\s+(\d{3})\s+(\d+|-)\s+"([^"]*)"\s+"([^"]*)"/' );

define('ATTACK_PATTERNS', [
    // SQLi
    '/union[\s+%09]+select/i'                                        => ['UNION SELECT',         's'],
    '/select[\s+%09].{0,80}from[\s+%09]/i'                          => ['SELECT FROM',          's'],
    '/\b(drop|truncate|alter)\s+(table|database)\b/i'               => ['DDL statement',        's'],
    '/\b(sleep|benchmark)\s*\(/i'                                   => ['Time-based blind',     's'],
    '/\bwaitfor\s+delay\b/i'                                        => ['WAITFOR DELAY',        's'],
    '/\b(extractvalue|updatexml)\s*\(/i'                            => ['Error-based SQLi',     's'],
    "/(?:'|%27)\s*(?:or|and)\s+['0-9]/i"                            => ['Boolean injection',    's'],
    '/(?:--|#|\/\*).{0,20}(?:select|drop|insert)/i'                  => ['Comment evasion',      's'],
    '/\bload_file\s*\(|into\s+(?:out|dump)file\b/i'               => ['File read/write',      's'],
    '/information_schema|pg_catalog\.pg_tables|sysobjects\b/i'      => ['Schema enumeration',   's'],
    "/(?:'|%27|%22)\s*(?:;|--|%23)/i"                                => ['Quote+comment',        's'],
    '/;[\s%09]*(?:select|insert|update|delete|drop)/i'               => ['Stacked query',        's'],
    // XSS
    '/<script[\s>\/]/i'                                             => ['script inject',        'x'],
    '/%3[Cc]script/i'                                                 => ['Encoded script',       'x'],
    '/\bon(?:load|error|click|focus|blur|submit|mouseover)\s*=/i'   => ['Event handler',        'x'],
    '/javascript\s*:/i'                                              => ['javascript proto',      'x'],
    '/\beval\s*\(/i'                                               => ['eval call',             'x'],
    '/<(?:svg|iframe|object|embed)[\s>\/]/i'                        => ['Dangerous tag',        'x'],
    '/document\s*\.\s*(?:cookie|write|location)/i'                 => ['DOM XSS',              'x'],
    '/(?:alert|prompt|confirm)\s*\(/i'                              => ['XSS probe',            'x'],
    "/src\\s*=\\s*['\"]?\\s*data\\s*:/i"                               => ['data URI',             'x'],
    '/\{\{.{0,60}\}\}|\$\{.{0,60}\}/i'                          => ['Template injection',   'x'],
    // Path Traversal
    '/(?:\.\.\/|%2e%2e|%252e)/i'                                   => ['Path traversal',       'p'],
    '/\/(?:etc\/passwd|etc\/shadow|etc\/hosts|proc\/self)/i'      => ['System file access',   'p'],
    '/\/(?:wp-config|\.env|\.git\/|\.htaccess|web\.config)/i'    => ['Config file probe',    'p'],
    '/\/(?:admin|phpmyadmin|pma|cpanel|plesk)(?:\/|$)/i'            => ['Admin panel probe',    'p'],
    // Scanners
    '/(?:nikto|sqlmap|nmap|masscan|zgrab|nuclei|gobuster|dirb|wfuzz|ffuf)/i' => ['Known scanner', 'c'],
    '/(?:python-requests|go-http-client|curl\/[0-9]|wget\/[0-9])/i' => ['Scripted client',     'c'],
    '/(?:shodan|censys|binaryedge|stretchoid)/i'                      => ['Internet scanner',     'c'],
]);

// Risk score ваги по категорії
const RISK_WEIGHTS = ['s' => 30, 'x' => 25, 'p' => 20, 'c' => 15];
const RISK_BONUS   = [
    'status_4xx'    => 2,   // кожен 4xx
    'status_5xx'    => 3,   // кожен 5xx
    'high_rps'      => 10,  // >100 запитів з одного IP
    'scan_ua'       => 20,  // User-Agent сканера
];

function parseNginxLog(string $content, int $limit = 5000000): array
{
    $ipCnt = $methodCnt = $errUrls = $bwIp = $dateCnt = [];
    $statusGroups = ['2xx' => 0, '3xx' => 0, '4xx' => 0, '5xx' => 0];
    $statuses = [];
    $sqliByIp = $sqliTypes = $sqliHits = [];
    $xssByIp  = $xssTypes  = $xssHits  = [];
    $pathByIp = $pathTypes = $pathHits = [];
    $scanByIp = $scanHits = [];
    $ipStatus4xx = $ipStatus5xx = [];  // для risk score
    $ipScanUa    = [];
    $total = $totalBytes = $parseErr = $bots = 0;
    $sqliTotal = $xssTotal = $pathTotal = $scanTotal = 0;
    $tlsProbes = $binaryLines = 0;
    $tsStart = PHP_INT_MAX;
    $tsEnd   = 0;
    $hourCnt = array_fill(0, 24, 0);

    $attackRx   = array_keys(ATTACK_PATTERNS);
    $attackMeta = array_values(ATTACK_PATTERNS);
    $nAttack    = count($attackRx);

    static $months = ['Jan'=>1,'Feb'=>2,'Mar'=>3,'Apr'=>4,'May'=>5,'Jun'=>6,
                      'Jul'=>7,'Aug'=>8,'Sep'=>9,'Oct'=>10,'Nov'=>11,'Dec'=>12];

    $offset = 0;
    $len    = strlen($content);
    $n      = 0;

    while ($offset < $len && $n < $limit) {
        $nl   = strpos($content, "\n", $offset);
        $line = $nl === false ? substr($content, $offset) : substr($content, $offset, $nl - $offset);
        $offset = $nl === false ? $len : $nl + 1;
        $line = rtrim($line, "\r");
        if ($line === '') continue;

        if (!preg_match(NGINX_RE, $line, $m)) {
            $b0 = isset($line[0]) ? ord($line[0]) : 0;
            if ($b0 === 0x16 || $b0 === 0x15 || $b0 === 0x14) { $tlsProbes++; }
            elseif (strpos($line, "\x16\x03") !== false)       { $tlsProbes++; }
            elseif ($b0 > 0 && $b0 < 0x20 && $b0 !== 0x09)    { $binaryLines++; }
            elseif (preg_match('/[\x00-\x08\x0b\x0e-\x1f]/', $line)) { $binaryLines++; }
            else { $parseErr++; }
            continue;
        }
        $n++;

        [, $ip, $time, $request, $statusStr, $bytesStr, $referer] = $m;
        $ua = $m[7] ?? '-';

        $parts  = explode(' ', $request, 3);
        $method = strtoupper($parts[0] ?? '-');
        $uri    = $parts[1] ?? '-';

        if (ord($method[0] ?? ' ') < 0x20 || strlen($method) > 10
            || !preg_match('/^[A-Z]{2,10}$/', $method)) {
            $tlsProbes++; continue;
        }

        $status = (int)$statusStr;
        $bytes  = $bytesStr === '-' ? 0 : (int)$bytesStr;
        $total++;
        $totalBytes += $bytes;

        match(true) {
            $status < 300 => $statusGroups['2xx']++,
            $status < 400 => $statusGroups['3xx']++,
            $status < 500 => $statusGroups['4xx']++,
            default       => $statusGroups['5xx']++,
        };
        isset($statuses[$status]) ? $statuses[$status]++ : $statuses[$status] = 1;

        $method = strtoupper($method);
        isset($methodCnt[$method]) ? $methodCnt[$method]++ : $methodCnt[$method] = 1;
        isset($ipCnt[$ip])  ? $ipCnt[$ip]++         : $ipCnt[$ip]  = 1;
        isset($bwIp[$ip])   ? $bwIp[$ip] += $bytes  : $bwIp[$ip]   = $bytes;

        // Для risk score — рахуємо 4xx/5xx по IP
        if ($status >= 400 && $status < 500) { isset($ipStatus4xx[$ip]) ? $ipStatus4xx[$ip]++ : $ipStatus4xx[$ip] = 1; }
        if ($status >= 500)                  { isset($ipStatus5xx[$ip]) ? $ipStatus5xx[$ip]++ : $ipStatus5xx[$ip] = 1; }

        if ($status === 404) {
            $p = ($q = strpos($uri, '?')) !== false ? substr($uri, 0, $q) : $uri;
            isset($errUrls[$p]) ? $errUrls[$p]++ : $errUrls[$p] = 1;
        }

        // Бот/сканер UA
        $uaLow = strtolower($ua);
        if (str_contains($uaLow,'bot') || str_contains($uaLow,'crawler')
            || str_contains($uaLow,'spider') || str_contains($uaLow,'scraper')) {
            $bots++;
        }
        // Відомі сканери в UA — окремо для risk score
        if (preg_match('/nikto|sqlmap|masscan|zgrab|nuclei|gobuster|dirb|wfuzz|ffuf|nmap/i', $ua)) {
            isset($ipScanUa[$ip]) ? $ipScanUa[$ip]++ : $ipScanUa[$ip] = 1;
        }

        // Час
        $h   = (int)substr($time, 12, 2);
        $hourCnt[$h]++;
        $dy  = (int)substr($time, 0, 2);
        $dmo = $months[substr($time, 3, 3)] ?? 1;
        $dyr = (int)substr($time, 7, 4);
        $dk  = sprintf('%04d-%02d-%02d', $dyr, $dmo, $dy);
        isset($dateCnt[$dk]) ? $dateCnt[$dk]++ : $dateCnt[$dk] = 1;

        $ts = mktime($h, (int)substr($time,15,2), (int)substr($time,18,2), $dmo, $dy, $dyr);
        if ($ts) {
            if ($tsStart === PHP_INT_MAX || $ts < $tsStart) $tsStart = $ts;
            if ($ts > $tsEnd) $tsEnd = $ts;
        }

        // ── Атаки ──
        $target = $uri . ' ' . $referer . ' ' . $ua;
        if (!_quickSuspiciousCheck($target)) continue;

        $decoded = urldecode($target);

        for ($i = 0; $i < $nAttack; $i++) {
            if (!preg_match($attackRx[$i], $decoded)) continue;
            [$label, $cat] = $attackMeta[$i];

            if ($cat === 's') {
                $sqliTotal++;
                isset($sqliByIp[$ip])     ? $sqliByIp[$ip]++     : $sqliByIp[$ip]     = 1;
                isset($sqliTypes[$label]) ? $sqliTypes[$label]++  : $sqliTypes[$label] = 1;
                if (count($sqliHits) < 300)
                    $sqliHits[] = [$ip, $time, $method, substr($uri,0,150), $status, $label];
            } elseif ($cat === 'x') {
                $xssTotal++;
                isset($xssByIp[$ip])      ? $xssByIp[$ip]++      : $xssByIp[$ip]      = 1;
                isset($xssTypes[$label])  ? $xssTypes[$label]++  : $xssTypes[$label]  = 1;
                if (count($xssHits) < 300)
                    $xssHits[] = [$ip, $time, $method, substr($uri,0,150), $status, $label];
            } elseif ($cat === 'p') {
                $pathTotal++;
                isset($pathByIp[$ip])     ? $pathByIp[$ip]++     : $pathByIp[$ip]     = 1;
                isset($pathTypes[$label]) ? $pathTypes[$label]++  : $pathTypes[$label] = 1;
                if (count($pathHits) < 300)
                    $pathHits[] = [$ip, $time, $method, substr($uri,0,150), $status, $label];
            } elseif ($cat === 'c') {
                $scanTotal++;
                isset($scanByIp[$ip])     ? $scanByIp[$ip]++     : $scanByIp[$ip]     = 1;
                if (count($scanHits) < 300)
                    $scanHits[] = [$ip, $time, $method, substr($uri,0,150), $status, $label];
            }
            break;
        }
    }

    arsort($ipCnt); arsort($errUrls); arsort($bwIp);
    arsort($sqliByIp); arsort($sqliTypes);
    arsort($xssByIp);  arsort($xssTypes);
    arsort($pathByIp); arsort($pathTypes);
    arsort($scanByIp); arsort($statuses);

    // ── Risk Score по IP ──
    $riskScores = [];
    $allAttackIps = array_unique(array_merge(
        array_keys($sqliByIp), array_keys($xssByIp),
        array_keys($pathByIp), array_keys($scanByIp)
    ));
    foreach ($allAttackIps as $ip) {
        $score = 0;
        $score += ($sqliByIp[$ip] ?? 0) * RISK_WEIGHTS['s'];
        $score += ($xssByIp[$ip]  ?? 0) * RISK_WEIGHTS['x'];
        $score += ($pathByIp[$ip] ?? 0) * RISK_WEIGHTS['p'];
        $score += ($scanByIp[$ip] ?? 0) * RISK_WEIGHTS['c'];
        $score += ($ipStatus4xx[$ip] ?? 0) * RISK_BONUS['status_4xx'];
        $score += ($ipStatus5xx[$ip] ?? 0) * RISK_BONUS['status_5xx'];
        if (($ipCnt[$ip] ?? 0) > 100) $score += RISK_BONUS['high_rps'];
        if (isset($ipScanUa[$ip]))     $score += RISK_BONUS['scan_ua'];
        $riskScores[$ip] = min(100, $score);
    }
    arsort($riskScores);

    // Зведені attack_top_ips (для зворотної сумісності з analyze.php)
    $attackIps = $sqliByIp;
    foreach ([$xssByIp, $pathByIp, $scanByIp] as $src) {
        foreach ($src as $ip => $c) { isset($attackIps[$ip]) ? $attackIps[$ip] += $c : $attackIps[$ip] = $c; }
    }
    arsort($attackIps);

    $errTotal = $statusGroups['4xx'] + $statusGroups['5xx'];
    $maxHour  = max($hourCnt);

    return [
        'type'           => 'nginx',
        'total'          => $total,
        'total_bytes'    => $totalBytes,
        'parse_errors'   => $parseErr,
        'tls_probes'     => $tlsProbes,
        'binary_lines'   => $binaryLines,
        'bots'           => $bots,
        'ts_start'       => $tsStart !== PHP_INT_MAX ? $tsStart : null,
        'ts_end'         => $tsEnd ?: null,
        'dates'          => (ksort($dateCnt) ? $dateCnt : $dateCnt),
        'statuses'       => $statuses,
        'status_groups'  => $statusGroups,
        'methods'        => $methodCnt,
        'hours'          => $hourCnt,
        'top_ips'        => array_slice($ipCnt,    0, 20, true),
        'top_404'        => array_slice($errUrls,  0, 15, true),
        'bw_by_ip'       => array_slice($bwIp,     0, 10, true),
        'unique_ips'     => count($ipCnt),
        'avg_bytes'      => $total > 0 ? intdiv($totalBytes, $total) : 0,
        'error_rate'     => $total > 0 ? round($errTotal / $total * 100, 1) : 0,
        'peak_hour'      => $maxHour > 0 ? array_search($maxHour, $hourCnt) : 0,
        // SQLi
        'sqli_total'     => $sqliTotal,
        'sqli_hits'      => $sqliHits,
        'sqli_by_ip'     => $sqliByIp,
        'sqli_types'     => $sqliTypes,
        // XSS
        'xss_total'      => $xssTotal,
        'xss_hits'       => $xssHits,
        'xss_by_ip'      => $xssByIp,
        'xss_types'      => $xssTypes,
        // Path Traversal
        'path_total'     => $pathTotal,
        'path_hits'      => $pathHits,
        'path_by_ip'     => $pathByIp,
        'path_types'     => $pathTypes,
        // Scanners
        'scan_total'     => $scanTotal,
        'scan_hits'      => $scanHits,
        'scan_by_ip'     => $scanByIp,
        // Risk Score
        'risk_scores'    => array_slice($riskScores, 0, 50, true),
        'attack_top_ips' => array_slice($attackIps,  0, 20, true),
    ];
}

function _quickSuspiciousCheck(string $s): bool {
    $low = strtolower($s);
    return str_contains($low, 'select')   || str_contains($low, 'union')
        || str_contains($low, 'script')   || str_contains($low, 'eval(')
        || str_contains($low, 'javascript')|| str_contains($low, 'sleep(')
        || str_contains($low, 'drop ')    || str_contains($low, 'onerror')
        || str_contains($low, 'onclick')  || str_contains($low, 'onload')
        || str_contains($low, '%3c')      || str_contains($s,   "'")
        || str_contains($s,   '"')        || str_contains($s,   '--')
        || str_contains($s,   '/*')       || str_contains($s,   '{{')
        || str_contains($low, '../')      || str_contains($low, '%2e%2e')
        || str_contains($low, '/etc/')    || str_contains($low, 'passwd')
        || str_contains($low, 'nikto')    || str_contains($low, 'sqlmap')
        || str_contains($low, 'nuclei')   || str_contains($low, 'gobuster')
        || str_contains($low, 'ffuf')     || str_contains($low, 'dirb')
        || str_contains($low, 'wfuzz')    || str_contains($low, '.env')
        || str_contains($low, '.git/')    || str_contains($low, 'wp-config')
        || str_contains($low, 'phpmyadmin');
}

function fmtBytes(int $b): string {
    if ($b <= 0) return '0 B';
    $u = ['B','KB','MB','GB','TB'];
    $i = min((int)floor(log($b, 1024)), 4);
    return round($b / (1024 ** $i), 2) . ' ' . $u[$i];
}

function statusBadge(int $c): string {
    $cls = match(true) {
        $c < 300 => 'badge-2xx', $c < 400 => 'badge-3xx',
        $c < 500 => 'badge-4xx', default  => 'badge-5xx',
    };
    return "<span class=\"badge $cls\">$c</span>";
}
