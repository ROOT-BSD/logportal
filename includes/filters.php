<?php
/* LogPortal — filters.php */

function filterByDate(string $content, string $type, int $tsFrom, int $tsTo, int $hintYear = 0): string
{
    static $months = ['Jan'=>1,'Feb'=>2,'Mar'=>3,'Apr'=>4,'May'=>5,'Jun'=>6,
                      'Jul'=>7,'Aug'=>8,'Sep'=>9,'Oct'=>10,'Nov'=>11,'Dec'=>12];
    $out      = '';
    $offset   = 0;
    $len      = strlen($content);
    $logYear  = ($hintYear >= 2000 && $hintYear <= 2099) ? $hintYear : (int)date('Y');

    while ($offset < $len) {
        $nl   = strpos($content, "\n", $offset);
        $line = $nl === false ? substr($content, $offset) : substr($content, $offset, $nl - $offset);
        $offset = $nl === false ? $len : $nl + 1;

        $ts = 0;
        if ($type === 'nginx') {
            // Nginx містить рік у форматі: [05/Mar/2026:13:40:47 +0200]
            if (preg_match('/\[(\d{2})\/(\w{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2})/', $line, $m))
                $ts = mktime((int)$m[4],(int)$m[5],(int)$m[6], $months[$m[2]]??1, (int)$m[1], (int)$m[3]);
        } elseif ($type === 'bind') {
            // BIND власний формат містить рік: 06-Mar-2026 12:34:56
            if (preg_match('/^(\d{2})-(\w{3})-(\d{4})\s+(\d{2}):(\d{2}):(\d{2})/', $line, $m))
                $ts = mktime((int)$m[4],(int)$m[5],(int)$m[6], $months[$m[2]]??1, (int)$m[1], (int)$m[3]);
            // Syslog формат BIND
            elseif (preg_match('/^(\w{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})/', $line, $m))
                $ts = mktime((int)$m[3],(int)$m[4],(int)$m[5], $months[$m[1]]??1, (int)$m[2], $logYear);
        } else {
            // Postfix syslog: "Mar  5 13:01:01"
            if (preg_match('/^(\w{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})/', $line, $m))
                $ts = mktime((int)$m[3],(int)$m[4],(int)$m[5], $months[$m[1]]??1, (int)$m[2], $logYear);
        }
        if ($ts && ($ts < $tsFrom || $ts > $tsTo)) continue;
        $out .= $line . "\n";
    }
    return $out;
}
