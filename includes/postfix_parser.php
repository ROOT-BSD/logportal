<?php
/* LogPortal — postfix_parser.php
   Парсер Postfix mail.log / syslog
   Підтримує: smtpd, smtp, qmgr, bounce, cleanup, pipe, local, error
*/

// Базовий syslog заголовок: "Mar  5 13:01:01 hostname postfix/daemon[pid]: message"
define('PF_RE',      '/^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\S+\s+postfix\/([\w\/-]+)\[\d+\]:\s+(.+)$/');
define('PF_QID_RE',  '/^([0-9A-Za-z]{6,20}):\s+(.+)$/');

function parsePostfixLog(string $content, int $limit = 5000000, int $hintYear = 0): array
{
    $queues   = [];   // qid => [from, to[], size, status, relay, delay, dsn, time]
    $hourCnt  = array_fill(0, 24, 0);
    $dayCnt   = [];
    $statuses = ['sent' => 0, 'bounced' => 0, 'deferred' => 0, 'expired' => 0];
    $daemons  = [];
    $rejects  = [];   // причини reject
    $rejectIps = [];
    $rejectFrom = [];
    $topRelays  = [];
    $topFrom    = [];
    $topTo      = [];
    $parseErr   = 0;
    $total      = 0;
    $totalSize  = 0;
    $connects   = 0;
    $disconnects = 0;
    $tsStart    = PHP_INT_MAX;
    $tsEnd      = 0;

    static $months = ['Jan'=>1,'Feb'=>2,'Mar'=>3,'Apr'=>4,'May'=>5,'Jun'=>6,
                      'Jul'=>7,'Aug'=>8,'Sep'=>9,'Oct'=>10,'Nov'=>11,'Dec'=>12];

    $curYear  = (int)date('Y');
    $curMonth = (int)date('n');
    // Рік: з шляху файлу якщо є, інакше поточний
    $logYear  = ($hintYear >= 2000 && $hintYear <= 2099) ? $hintYear : $curYear;

    $offset = 0;
    $len    = strlen($content);
    $n      = 0;

    while ($offset < $len && $n < $limit) {
        $nl   = strpos($content, "\n", $offset);
        $line = $nl === false ? substr($content, $offset) : substr($content, $offset, $nl - $offset);
        $offset = ($nl === false) ? $len : $nl + 1;
        $line = rtrim($line, "\r");
        if ($line === '') continue;
        $n++;

        if (!preg_match(PF_RE, $line, $m)) {
            // ── Amavis рядки: прив'язуємо Subject та X-Mailer через queued_as → QID postfix ──
            // "amavis[pid]: ... Queue-ID: XXXX, ... queued_as: YYYY, Subject: "...", From: <...>"
            if (str_contains($line, 'amavis') && str_contains($line, 'queued_as:')) {
                $subj  = '';
                $qidOut = '';
                if (preg_match('/queued_as:\s*(\S+?)(?:,|$)/i', $line, $am)) $qidOut = strtoupper(rtrim($am[1], ','));
                if (preg_match('/Subject:\s*"([^"]*)"/i', $line, $sm))        $subj   = _pfDecodeSubject($sm[1]);
                if ($qidOut && $subj) {
                    if (!isset($queues[$qidOut])) $queues[$qidOut] = _pfEmptyMsg();
                    if (empty($queues[$qidOut]['subject'])) $queues[$qidOut]['subject'] = $subj;
                }
                // X-Mailer з amavis рядка
                if ($qidOut && preg_match('/X-Mailer:\s*"([^"]*)"/i', $line, $xm)) {
                    if (!isset($queues[$qidOut])) $queues[$qidOut] = _pfEmptyMsg();
                    if (empty($queues[$qidOut]['xmailer'])) $queues[$qidOut]['xmailer'] = trim($xm[1]);
                }
            }
            // ── cleanup: warning: header X-Mailer: ... from ... ──
            // postfix/cleanup[pid]: QQQQ: warning: header X-Mailer: The Bat! from ...
            if (str_contains($line, 'cleanup') && preg_match(PF_RE, $line, $hm)) {
                $hqid = strtoupper($hm[2] ?? '');
                $hmsg = $hm[3] ?? '';
                if ($hqid && preg_match('/(?:warning:\s*)?header\s+X-Mailer:\s*(.+?)\s+from\b/i', $hmsg, $xm)) {
                    if (!isset($queues[$hqid])) $queues[$hqid] = _pfEmptyMsg();
                    if (empty($queues[$hqid]['xmailer'])) $queues[$hqid]['xmailer'] = trim($xm[1]);
                }
            }
            // Рядки від clamd, dovecot тощо — тихо пропускаємо
            if (!preg_match('/^\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+\S+/', $line)) {
                $parseErr++;
            }
            continue;
        }
        [, $timeStr, $daemon, $msg] = $m;

        // Нормалізуємо: submission/smtpd → smtpd, 10025/smtpd → smtpd, amavis/smtp → smtp
        $daemonBase = str_contains($daemon, '/') ? substr($daemon, strrpos($daemon, '/') + 1) : $daemon;

        $total++;

        // Парсинг часу: "Mar  5 13:01:01" — без року
        // Рік: якщо відомий з шляху файлу — точний, інакше евристика по місяцю
        $tparts = preg_split('/\s+/', trim($timeStr));
        if (count($tparts) === 3) {
            [$mon, $day, $hms] = $tparts;
            [$hh, $mm, $ss]   = explode(':', $hms);
            $logMonth = $months[$mon] ?? 1;
            $ts = mktime((int)$hh, (int)$mm, (int)$ss, $logMonth, (int)$day, $logYear);
            if ($ts < $tsStart) $tsStart = $ts;
            if ($ts > $tsEnd)   $tsEnd   = $ts;
            $hourCnt[(int)$hh]++;
            $dk = sprintf('%04d-%02d-%02d', $logYear, $logMonth, (int)$day);
            isset($dayCnt[$dk]) ? $dayCnt[$dk]++ : $dayCnt[$dk] = 1;
        }

        // Лічильник демонів
        // Лічильник: повне ім'я (submission/smtpd, amavis/smtp тощо)
        isset($daemons[$daemon]) ? $daemons[$daemon]++ : $daemons[$daemon] = 1;

        // ── smtpd: підключення та відхилення ──
        if ($daemonBase === 'smtpd') {
            if (str_starts_with($msg, 'connect from '))    { $connects++; continue; }
            if (str_starts_with($msg, 'disconnect from ')) { $disconnects++; continue; }

            // REJECT / NOQUEUE reject
            if (str_contains($msg, 'reject:') || str_contains($msg, 'NOQUEUE')) {
                _pfParseReject($msg, $rejects, $rejectIps, $rejectFrom);
                continue;
            }
        }

        // ── Повідомлення з queue ID ──
        // Виключаємо рядки що не є Queue ID (NOQUEUE, warning, fatal тощо)
        static $notQid = ['NOQUEUE','warning','fatal','panic','error','info',
                          'connect','disconnect','lost','timeout','reject'];
        if (!preg_match(PF_QID_RE, $msg, $qm)) continue;
        if (in_array($qm[1], $notQid, true)) continue;
        [, $qid, $rest] = $qm;
        $qid = strtoupper($qid);

        if ($daemonBase === 'qmgr' || $daemonBase === 'cleanup') {
            // from=<addr>, size=N, message-id=, subject=
            if (preg_match('/from=<([^>]*)>/', $rest, $fm)) {
                $from = strtolower($fm[1]);
                if ($from) {
                    isset($topFrom[$from]) ? $topFrom[$from]++ : $topFrom[$from] = 1;
                }
                if (!isset($queues[$qid])) $queues[$qid] = _pfEmptyMsg();
                $queues[$qid]['from'] = $from;
            }
            if (preg_match('/size=(\d+)/', $rest, $szm)) {
                if (!isset($queues[$qid])) $queues[$qid] = _pfEmptyMsg();
                $queues[$qid]['size'] = (int)$szm[1];
                $totalSize += (int)$szm[1];
            }
            // subject= (з amavis/cleanup header checks)
            // Формат 1: subject="текст (raw: =?UTF-8?B?...?=)"
            // Формат 2: subject="=?UTF-8?B?...?="
            // Формат 3: subject=plain text
            if (preg_match('/\bsubject=("(?:[^"\\\\]|\\\\.)*"|[^\s,;]+(?:\s+[^\s,;]+)*?)(?:$|,|\s{2})/i', $rest, $subm)) {
                if (!isset($queues[$qid])) $queues[$qid] = _pfEmptyMsg();
                if (empty($queues[$qid]['subject'])) {
                    $queues[$qid]['subject'] = _pfDecodeSubject($subm[1]);
                }
            }
            // x-mailer= (агент відправки, напр. "The Bat! 10.0", "Microsoft Outlook 16.0")
            if (preg_match('/\bx-mailer=("(?:[^"\\\\]|\\\\.)*"|[^\s,;][^,;]*?)(?:$|,|\s{2})/i', $rest, $xm)) {
                if (!isset($queues[$qid])) $queues[$qid] = _pfEmptyMsg();
                if (empty($queues[$qid]['xmailer'])) {
                    $queues[$qid]['xmailer'] = trim(trim($xm[1], '"'));
                }
            }
            // Зберігаємо час першої появи qid
            if (isset($ts) && $ts && isset($queues[$qid]) && !$queues[$qid]['time']) {
                $queues[$qid]['time'] = $ts;
            }
            continue;
        }

        if ($daemonBase === 'smtp' || $daemonBase === 'local' || $daemonBase === 'pipe' || $daemonBase === 'virtual') {
            if (!isset($queues[$qid])) $queues[$qid] = _pfEmptyMsg();

            // to=<addr>
            if (preg_match('/to=<([^>]*)>/', $rest, $tm)) {
                $to = strtolower($tm[1]);
                if ($to) {
                    isset($topTo[$to]) ? $topTo[$to]++ : $topTo[$to] = 1;
                    if (!in_array($to, $queues[$qid]['to'])) $queues[$qid]['to'][] = $to;
                }
            }

            // status=sent|bounced|deferred|expired
            if (preg_match('/status=(\w+)/', $rest, $stm)) {
                $st = $stm[1];
                if (isset($statuses[$st])) $statuses[$st]++;
                $queues[$qid]['status'] = $st;

                // Причина для deferred та bounced — текст після status=xxx (...)
                if (($st === 'deferred' || $st === 'bounced') && empty($queues[$qid]['reason'])) {
                    // Формат: status=deferred (reason text here)
                    if (preg_match('/status=\w+\s+\((.+)\)\s*$/', $rest, $rm)) {
                        $queues[$qid]['reason'] = trim($rm[1]);
                    }
                    // Альтернатив: status=bounced (delivery temporarily suspended: ...)
                    elseif (preg_match('/status=\w+\s+(.+)$/', $rest, $rm)) {
                        $reason = trim($rm[1]);
                        // Прибираємо зайві дужки якщо весь рядок в них
                        $reason = trim($reason, '()');
                        if (strlen($reason) > 5) {
                            $queues[$qid]['reason'] = $reason;
                        }
                    }
                }
            }

            // relay=host[ip]:port
            if (preg_match('/relay=(\S+)/', $rest, $rm)) {
                $relay = preg_replace('/\[.*?\].*$/', '', $rm[1]);
                $relay = rtrim($relay, ',');
                static $skipRelays = ['none', '127.0.0.1', 'localhost', 'dovecot', ''];
                if ($relay && !in_array(strtolower($relay), $skipRelays, true)
                    && !str_starts_with($relay, '127.')
                    && !str_starts_with($relay, '::1')) {
                    isset($topRelays[$relay]) ? $topRelays[$relay]++ : $topRelays[$relay] = 1;
                }
            }

            // delay=N
            if (preg_match('/delay=([\d.]+)/', $rest, $dm)) {
                $queues[$qid]['delay'] = (float)$dm[1];
            }
            // dsn=N.N.N
            if (preg_match('/dsn=([\d.]+)/', $rest, $dsnm)) {
                $queues[$qid]['dsn'] = $dsnm[1];
            }
            // Час доставки
            if (isset($ts) && $ts && !$queues[$qid]['time']) {
                $queues[$qid]['time'] = $ts;
            }
        }

        if ($daemonBase === 'bounce') {
            $statuses['bounced']++;
        }
    }

    // Сортування
    arsort($rejects); arsort($rejectIps); arsort($rejectFrom);
    arsort($topRelays); arsort($topFrom); arsort($topTo);
    arsort($daemons);
    ksort($dayCnt);

    // Затримки — середня та максимальна
    $delays = array_filter(array_column($queues, 'delay'));
    $avgDelay = $delays ? round(array_sum($delays) / count($delays), 2) : 0;
    $maxDelay = $delays ? round(max($delays), 2) : 0;

    $sent     = $statuses['sent'];
    $rejected = array_sum($rejects);
    $msgTotal = $sent + $statuses['bounced'] + $statuses['deferred'] + $statuses['expired'];

    return [
        'type'          => 'postfix',
        'total_lines'   => $total,
        'parse_errors'  => $parseErr,
        'ts_start'      => $tsStart !== PHP_INT_MAX ? $tsStart : null,
        'ts_end'        => $tsEnd ?: null,
        'hours'         => $hourCnt,
        'days'          => $dayCnt,
        'peak_hour'     => $hourCnt ? array_search(max($hourCnt), $hourCnt) : 0,
        // З'єднання
        'connects'      => $connects,
        'disconnects'   => $disconnects,
        // Повідомлення
        'msg_total'     => $msgTotal,
        'sent'          => $sent,
        'bounced'       => $statuses['bounced'],
        'deferred'      => $statuses['deferred'],
        'expired'       => $statuses['expired'],
        'total_size'    => $totalSize,
        'avg_delay'     => $avgDelay,
        'max_delay'     => $maxDelay,
        // Відхилення
        'rejected'      => $rejected,
        'reject_reasons'=> array_slice($rejects,    0, 15, true),
        'reject_ips'    => array_slice($rejectIps,  0, 15, true),
        'reject_from'   => array_slice($rejectFrom, 0, 15, true),
        // Топ
        'top_relays'    => array_slice($topRelays, 0, 15, true),
        'top_from'      => array_slice($topFrom,   0, 15, true),
        'top_to'        => array_slice($topTo,     0, 15, true),
        'daemons'       => $daemons,
        'unique_senders'=> count($topFrom),
        'unique_rcpt'   => count($topTo),
        'messages'      => $queues,
    ];
}

function _pfParseReject(string $msg, array &$reasons, array &$ips, array &$froms): void
{
    // Витягуємо IP відправника
    if (preg_match('/from \S+\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]/', $msg, $m)) {
        isset($ips[$m[1]]) ? $ips[$m[1]]++ : $ips[$m[1]] = 1;
    }
    // Витягуємо from=
    if (preg_match('/from=<([^>]+)>/', $msg, $m)) {
        $f = strtolower($m[1]);
        isset($froms[$f]) ? $froms[$f]++ : $froms[$f] = 1;
    }
    // Причина: код DSN + текст до крапки з комою
    $reason = 'Unknown reject';
    if (preg_match('/:\s+(\d{3}\s+\d+\.\d+\.\d+\s+[^;]+)/', $msg, $m)) {
        $reason = trim(substr($m[1], 0, 60));
    } elseif (preg_match('/reject:\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+:\s+(\d{3}\s+[^;]+)/', $msg, $m)) {
        $reason = trim(substr($m[1], 0, 60));
    } elseif (preg_match('/NOQUEUE:\s+reject:\s+\S+\s+\S+\s+\S+\s+[^:]+:\s+(\d{3}[^;]+)/', $msg, $m)) {
        $reason = trim(substr($m[1], 0, 60));
    }
    isset($reasons[$reason]) ? $reasons[$reason]++ : $reasons[$reason] = 1;
}

function _pfEmptyMsg(): array {
    return ['from' => '', 'to' => [], 'size' => 0, 'status' => '', 'relay' => '', 'delay' => 0, 'dsn' => '', 'subject' => '', 'time' => 0, 'reason' => '', 'xmailer' => ''];
}

/**
 * Декодує Subject з MIME encoded-words (=?UTF-8?B?...?= та =?UTF-8?Q?...?=)
 * Підтримує формат Postfix: "текст (raw: =?...?=\t=?...?=)"
 */
function _pfDecodeSubject(string $raw): string {
    if ($raw === '') return '';
    $raw = trim($raw, '"\'');

    // Postfix логує: "decoded text (raw: =?UTF-8?...?=)"
    // raw частина може бути обрізана → encoded-words незавершені і не декодуються
    // Стратегія: якщо decoded частина перед (raw:) є читабельним текстом — використовуємо її
    $decodedPart = '';
    $rawPart     = '';

    if (preg_match('/^(.*?)\s*\(raw:\s*(.+?)\)\s*$/s', $raw, $m)) {
        // повний рядок з закритою дужкою
        $decodedPart = trim($m[1]);
        $rawPart     = trim($m[2]);
    } elseif (preg_match('/^(.*?)\s*\(raw:\s*(.*)$/s', $raw, $m)) {
        // raw обрізаний — дужка не закрита
        $decodedPart = trim($m[1]);
        $rawPart     = trim($m[2]);
    }

    // Функція декодування encoded-words
    $decode = function(string $s): string {
        $s = str_replace("\t", ' ', $s);
        $s = preg_replace('/\?=\s+=\?/', '?==?', $s);
        return preg_replace_callback(
            '/=\?([^?]+)\?([BbQq])\?([^?]*)\?=/',
            function(array $m) {
                [$full, $charset, $enc, $data] = $m;
                $enc = strtoupper($enc);
                try {
                    $bytes = $enc === 'B'
                        ? base64_decode(str_pad($data, (int)(ceil(strlen($data)/4)*4), '='))
                        : quoted_printable_decode(str_replace('_', ' ', $data));
                    $result = mb_convert_encoding($bytes, 'UTF-8', $charset);
                    return $result !== false ? $result : $full;
                } catch (\Throwable) {
                    return $full;
                }
            },
            $s
        );
    };

    if ($decodedPart !== '' || $rawPart !== '') {
        // Намагаємось декодувати raw частину
        $fromRaw = $rawPart !== '' ? trim(preg_replace('/\s+/', ' ', $decode($rawPart))) : '';
        // Якщо raw декодувався без залишкових =? — використовуємо його (повніший текст)
        // Інакше беремо decoded частину перед (raw:) — вона вже читабельна
        if ($fromRaw !== '' && !str_contains($fromRaw, '=?')) {
            $result = $fromRaw;
        } else {
            $result = $decodedPart !== ''
                ? trim(preg_replace('/\s+/', ' ', $decode($decodedPart)))
                : $fromRaw;
        }
    } else {
        // Немає (raw:) — декодуємо весь рядок
        $result = trim(preg_replace('/\s+/', ' ', $decode($raw)));
    }

    // Якщо тема починається з "docflow:" — показуємо тільки текст після префіксу,
    // обрізаємо на першій "(" (обрізаний хвіст, дужки пояснень тощо)
    if (preg_match('/^docflow:\s*(.+)/iu', $result, $dm)) {
        $result = trim(preg_replace('/\s*\(.*$/u', '', trim($dm[1])), " \t\r\n,;");
    }

    return $result;
}

// Визначення типу лог-файлу за першим рядком
function detectLogType(string $content): string {
    $first = substr($content, 0, 8000);
    if (preg_match('/postfix\/\w+\[\d+\]/', $first)) return 'postfix';
    if (preg_match('/\[\d{2}\/\w{3}\/\d{4}:\d{2}:\d{2}:\d{2}/', $first)) return 'nginx';
    if (preg_match('/" (?:GET|POST|HEAD|PUT|DELETE|PATCH|OPTIONS) |\] "(?:GET|POST|HEAD|PUT|DELETE|PATCH|OPTIONS) /', $first)) return 'nginx';
    if (preg_match('/named\[\d+\].*query:|client\s+[\d.]+#\d+.*query:\s+\S+\s+IN\s+\w+/', $first)) return 'bind';
    if (preg_match('/\d{2}-\w{3}-\d{4}\s+\d{2}:\d{2}:\d{2}\.\d+\s+client\s+(?:@\S+\s+)?[\d.]+#\d+/', $first)) return 'bind';
    // Mikrotik: теми firewall/dhcp/pppoe або формат дати mar/09/2026
    if (preg_match('/\b(?:firewall|dhcp|pppoe|l2tp|sstp|ovpn|pptp|bridge),(?:info|warning|error|critical)\b/i', $first)) return 'mikrotik';
    if (preg_match('/^[a-z]{3}\/\d{2}\/\d{4}\s+\d{2}:\d{2}:\d{2}/im', $first)) return 'mikrotik';
    if (preg_match('/\bRouterOS\b|\bMikroTik\b/i', $first)) return 'mikrotik';
    return 'nginx';
}
