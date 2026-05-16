<?php

/*
|--------------------------------------------------------------------------
| php/local_scan.php
| Heuristic pre-scan: runs before the AI to detect anomalies locally.
|
| New rules added (without interrupting existing logic):
|   • BRUTE_FORCE   — only flagged when the SAME IP has >= 3 failed logins
|   • ADMIN_UNKNOWN — unknown IP logged in successfully to an admin account
|--------------------------------------------------------------------------
*/

function localAnomalyScan(string $logs): array
{
    $lines    = explode("\n", $logs);
    $anomalies = [];

    /* ── Tracking buckets ── */
    $ipActivity    = [];
    $userFails     = [];
    $httpErrors    = [];
    $outboundBytes = [];
    $uncommonPorts = [];
    $dnsQueries    = [];
    $processEvents = [];

    /* ── Known-benign IPs ── */
    $benignIPs = ['127.0.0.1', '::1', '10.0.0.1'];

    /* ── Known admin usernames/paths ── */
    $adminKeywords = ['admin', 'administrator', 'root', 'superuser', 'sysadmin'];

    /* ── Known / trusted IP ranges (edit to match your environment) ── */
    $trustedIPPrefixes = ['192.168.', '10.', '172.16.', '127.'];

    /* ── Known-service ports ── */
    $knownSvcPorts = [22, 25, 53, 80, 110, 143, 443, 3306, 5432, 6379, 8080, 8443];

    /* ── Per-IP failed login counter (for brute-force detection) ── */
    $ipFailCount = [];

    /* ── Successful admin logins tracker ── */
    $adminLoginIPs = [];

    foreach ($lines as $line) {

        $line = trim($line);
        if (empty($line)) { continue; }

        /*
        |----------------------------------------------------------------------
        | IP EXTRACTION
        |----------------------------------------------------------------------
        */

        preg_match_all('/\b(\d{1,3}(?:\.\d{1,3}){3})\b/', $line, $ipMatches);
        $ips = array_unique($ipMatches[1] ?? []);

        /*
        |----------------------------------------------------------------------
        | TIMESTAMP
        |----------------------------------------------------------------------
        */

        $ts = 0;

        if (preg_match('/(\d{10})/', $line, $m)) {
            $ts = (int)$m[1];
        } elseif (preg_match('/(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})/', $line, $m)) {
            $ts = strtotime($m[1]);
        }

        /*
        |----------------------------------------------------------------------
        | PORT
        |----------------------------------------------------------------------
        */

        $port = null;

        if (preg_match('/[:\s](\d{2,5})\b/', $line, $m)) {
            $tmp = (int)$m[1];
            if ($tmp < 65536) { $port = $tmp; }
        }

        /*
        |----------------------------------------------------------------------
        | HTTP STATUS
        |----------------------------------------------------------------------
        */

        $httpStatus = null;

        if (preg_match('/\b(200|201|204|301|302|400|401|403|404|405|429|500|502|503)\b/', $line, $m)) {
            $httpStatus = (int)$m[1];
        }

        /*
        |----------------------------------------------------------------------
        | BYTES
        |----------------------------------------------------------------------
        */

        $bytes = 0;

        if (preg_match('/\b(\d{6,})\b/', $line, $m)) {
            $bytes = (int)$m[1];
        }

        /*
        |----------------------------------------------------------------------
        | USERNAME
        |----------------------------------------------------------------------
        */

        $user = null;

        if (preg_match('/user[=:\s]+([a-zA-Z0-9_\-\.@]+)/i', $line, $m)) {
            $user = strtolower($m[1]);
        } elseif (preg_match('/for\s+(?:invalid\s+user\s+)?([a-zA-Z0-9_\-\.@]+)\s+from/i', $line, $m)) {
            $user = strtolower($m[1]);
        }

        /*
        |----------------------------------------------------------------------
        | HIGH ENTROPY — Possible encoded payload
        |----------------------------------------------------------------------
        */

        if (preg_match('/[A-Za-z0-9+\/=]{40,}/', $line, $m)) {
            if (shannonEntropy($m[0]) > 4.5) {
                $anomalies[] = "[ANOMALY:HIGH_ENTROPY] Possible encoded payload detected.";
            }
        }

        /*
        |----------------------------------------------------------------------
        | PER-IP TRACKING
        |----------------------------------------------------------------------
        */

        foreach ($ips as $ip) {

            if (in_array($ip, $benignIPs)) { continue; }

            if (!isset($ipActivity[$ip])) {
                $ipActivity[$ip] = ['count' => 0, 'ports' => [], 'times' => []];
            }

            $ipActivity[$ip]['count']++;

            if ($ts) { $ipActivity[$ip]['times'][] = $ts; }

            if ($port) {
                $ipActivity[$ip]['ports'][$port] = ($ipActivity[$ip]['ports'][$port] ?? 0) + 1;
            }

            if ($httpStatus && $httpStatus >= 400) {
                $httpErrors[$ip][$httpStatus] = ($httpErrors[$ip][$httpStatus] ?? 0) + 1;
            }

            if ($bytes > 0) {
                $outboundBytes[$ip] = ($outboundBytes[$ip] ?? 0) + $bytes;
            }

            if ($port && $port > 1024 && !in_array($port, $knownSvcPorts)) {
                $uncommonPorts[$ip][$port] = ($uncommonPorts[$ip][$port] ?? 0) + 1;
            }
        }

        /*
        |----------------------------------------------------------------------
        | AUTH FAILURES — track per user (for userFails bucket)
        |----------------------------------------------------------------------
        */

        if (preg_match('/fail|invalid|incorrect|denied|refused|bad\s+(pass|auth|cred)/i', $line)) {

            $srcIP = $ips[0] ?? 'unknown';

            if ($user) {
                if (!isset($userFails[$user])) {
                    $userFails[$user] = ['count' => 0, 'ips' => []];
                }
                $userFails[$user]['count']++;
                $userFails[$user]['ips'][$srcIP] = true;
            }
        }

        /*
        |----------------------------------------------------------------------
        | FAILED LOGIN EVENTS — per-IP counter for brute force detection
        |----------------------------------------------------------------------
        */

        if (preg_match('/failed password|invalid user|authentication failure|login failed/i', $line)) {
            preg_match('/\b(\d{1,3}(?:\.\d{1,3}){3})\b/', $line, $ipMatch);
            $ip = $ipMatch[1] ?? 'Unknown';
            if ($ip !== 'Unknown') {
                $ipFailCount[$ip] = ($ipFailCount[$ip] ?? 0) + 1;
            }
        }

        /*
        |----------------------------------------------------------------------
        | SUCCESSFUL ADMIN LOGINS — track IPs that logged in as admin accounts
        |----------------------------------------------------------------------
        */

        $isSuccessfulLogin =
            preg_match('/accepted password|session opened|login successful|logged in|authentication success/i', $line);

        if ($isSuccessfulLogin && $user) {
            $isAdminUser = false;
            foreach ($adminKeywords as $keyword) {
                if (strpos($user, $keyword) !== false) {
                    $isAdminUser = true;
                    break;
                }
            }
            if ($isAdminUser) {
                $srcIP = $ips[0] ?? 'Unknown';
                if ($srcIP !== 'Unknown') {
                    $adminLoginIPs[$srcIP][] = $user;
                }
            }
        }

        /*
        |----------------------------------------------------------------------
        | DNS EXFIL
        |----------------------------------------------------------------------
        */

        if (preg_match('/query\[A\]\s+([\w\.\-]+)\s+from\s+(\d{1,3}(?:\.\d{1,3}){3})/i', $line, $m)) {
            $domain = $m[1];
            $srcIP  = $m[2];
            if (strlen($domain) > 50 || preg_match('/[a-z0-9]{20,}\./i', $domain)) {
                $dnsQueries[$srcIP][$domain] = ($dnsQueries[$srcIP][$domain] ?? 0) + 1;
            }
        }

        /*
        |----------------------------------------------------------------------
        | SUSPICIOUS PROCESSES
        |----------------------------------------------------------------------
        */

        if (preg_match('/(?:exec|spawn|cmd|process|command).*?[:\s]+([\w\/\\\\.]+(?:\.exe|\.sh|\.py|\.ps1)?)/i', $line, $m)) {
            $proc = strtolower(trim($m[1]));
            $host = $ips[0] ?? 'localhost';
            $badProcs = ['powershell','cmd.exe','bash','nc','netcat','wget','curl','certutil','mshta','wscript','cscript','regsvr32','rundll32'];
            foreach ($badProcs as $bp) {
                if (strpos($proc, $bp) !== false) {
                    $processEvents[$host][$proc] = ($processEvents[$host][$proc] ?? 0) + 1;
                }
            }
        }
    }

    /* ══════════════════════════════════════════════════════════════════════
       POST-LOOP ANALYSIS
    ══════════════════════════════════════════════════════════════════════ */

    /*
    |--------------------------------------------------------------------------
    | HIGH VELOCITY
    |--------------------------------------------------------------------------
    */

    foreach ($ipActivity as $ip => $data) {
        if (count($data['times']) >= 2) {
            $span = max($data['times']) - min($data['times']);
            $rate = $span > 0 ? ($data['count'] / $span) : $data['count'];
            if ($data['count'] > 100 && $span < 60) {
                $anomalies[] = "[ANOMALY:HIGH_VELOCITY] IP $ip made {$data['count']} requests in {$span}s (~" . round($rate, 1) . " req/s).";
            }
        }

        /*
        |----------------------------------------------------------------------
        | PORT SWEEP
        |----------------------------------------------------------------------
        */

        if (count($data['ports']) > 15) {
            $anomalies[] = "[ANOMALY:PORT_SWEEP] IP $ip contacted " . count($data['ports']) . " unique ports.";
        }
    }

    /*
    |--------------------------------------------------------------------------
    | BRUTE FORCE — Only flag when SAME IP has >= 3 failed login attempts
    |--------------------------------------------------------------------------
    */

    foreach ($ipFailCount as $ip => $count) {
        if ($count >= 3) {
            $anomalies[] = "[ANOMALY:BRUTE_FORCE] IP $ip generated $count failed login attempts. Possible brute force attack.";
        }
    }

    /*
    |--------------------------------------------------------------------------
    | UNKNOWN IP LOGGED INTO ADMIN ACCOUNT
    | Flag any IP that successfully authenticated as admin and is NOT trusted
    |--------------------------------------------------------------------------
    */

    foreach ($adminLoginIPs as $ip => $users) {
        $isTrusted = false;
        foreach ($trustedIPPrefixes as $prefix) {
            if (strpos($ip, $prefix) === 0) {
                $isTrusted = true;
                break;
            }
        }
        if (!$isTrusted) {
            $uniqueUsers = implode(', ', array_unique($users));
            $anomalies[] = "[ANOMALY:UNKNOWN_ADMIN_LOGIN] Untrusted IP $ip successfully logged in as admin account(s): $uniqueUsers. Possible account compromise.";
        }
    }

    /*
    |--------------------------------------------------------------------------
    | HTTP ERROR STORMS
    |--------------------------------------------------------------------------
    */

    foreach ($httpErrors as $ip => $codes) {
        $total404 = $codes[404] ?? 0;
        $total403 = $codes[403] ?? 0;
        if ($total404 > 30) {
            $anomalies[] = "[ANOMALY:DIR_SCAN] IP $ip generated {$total404} HTTP 404s.";
        }
        if ($total403 > 20) {
            $anomalies[] = "[ANOMALY:AUTH_SCAN] IP $ip generated {$total403} HTTP 403s.";
        }
    }

    /*
    |--------------------------------------------------------------------------
    | LARGE TRANSFERS
    |--------------------------------------------------------------------------
    */

    foreach ($outboundBytes as $ip => $bytes) {
        if ($bytes > 50 * 1048576) {
            $mb = round($bytes / 1048576, 1);
            $anomalies[] = "[ANOMALY:LARGE_TRANSFER] IP $ip transferred {$mb}MB outbound.";
        }
    }

    /*
    |--------------------------------------------------------------------------
    | UNCOMMON PORTS
    |--------------------------------------------------------------------------
    */

    foreach ($uncommonPorts as $ip => $ports) {
        if (count($ports) > 5) {
            $portList = implode(', ', array_keys($ports));
            $anomalies[] = "[ANOMALY:UNCOMMON_PORTS] IP $ip connected to unusual ports: $portList";
        }
    }

    /*
    |--------------------------------------------------------------------------
    | DNS TUNNELING
    |--------------------------------------------------------------------------
    */

    foreach ($dnsQueries as $ip => $domains) {
        if (count($domains) >= 3) {
            $anomalies[] = "[ANOMALY:DNS_EXFIL] IP $ip made suspicious DNS queries.";
        }
    }

    /*
    |--------------------------------------------------------------------------
    | SUSPICIOUS PROCESS EXECUTION
    |--------------------------------------------------------------------------
    */

    foreach ($processEvents as $host => $procs) {
        foreach ($procs as $proc => $count) {
            $anomalies[] = "[ANOMALY:SUSPICIOUS_PROCESS] Host $host executed '$proc' {$count} times.";
        }
    }

    return array_unique($anomalies);
}
