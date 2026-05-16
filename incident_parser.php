<?php

/*
|--------------------------------------------------------------------------
| incident_parser.php
|
| ROOT CAUSE FIX:
|   The AI outputs **bold** markdown on EVERY field label AND value, e.g.:
|     **Attack Type:** SQL Injection
|     **Severity:** High
|     **Source:** 192.168.1.5
|   The old regex  /^Attack Type:\s*(.+)$/m  never matched because **
|   prefixed the field name, breaking the ^ anchor.
|
|   Fix: strip ALL markdown FIRST, then parse clean plain text.
|--------------------------------------------------------------------------
*/

function parseIncidents(string $text, string $logs = ''): array
{
    $incidents = [];

    /*
    |--------------------------------------------------------------------------
    | STEP 1 — STRIP MARKDOWN COMPLETELY
    |--------------------------------------------------------------------------
    */

    $clean = $text;
    $clean = preg_replace('/\*{1,3}/',    '',   $clean);   // *** ** *
    $clean = preg_replace('/_{1,2}/',     '',   $clean);   // __ _
    $clean = preg_replace('/`([^`]*)`/s', '$1', $clean);   // `code`
    $clean = preg_replace('/^#+\s*/m',   '',   $clean);   // ## headings
    $clean = preg_replace('/\n{3,}/',  "\n\n", $clean);   // extra blank lines

    /*
    |--------------------------------------------------------------------------
    | STEP 2 — SPLIT ON "Incident:" BOUNDARY
    | Case-insensitive; tolerates leading spaces, hyphens, numbers
    | e.g. "Incident 1:", "- Incident:", "INCIDENT:"
    |--------------------------------------------------------------------------
    */

    $blocks = preg_split(
        '/^\s*(?:[-\d.]+\s*)?Incident\s*\d*\s*:/mi',
        $clean,
        -1,
        PREG_SPLIT_NO_EMPTY
    );

    foreach ($blocks as $block) {

        $block = trim($block);
        if (empty($block)) { continue; }

        $incident = [];

        $fields = [
            'Attack Type',
            'Severity',
            'Confidence',
            'Source',
            'Target',
            'Description',
            'Evidence',
        ];

        /*
        |----------------------------------------------------------------------
        | STEP 3 — EXTRACT EACH FIELD
        | flexLabel turns "Attack Type" → "Attack\s*Type" so partial spaces
        | surviving markdown strip still match.
        |----------------------------------------------------------------------
        */

        foreach ($fields as $field) {
            $flexLabel = preg_replace('/\s+/', '\s*', preg_quote($field, '/'));
            // Match to end-of-line; value may contain anything except newline
            $pattern = '/^\s*' . $flexLabel . '\s*:\s*(.+)$/mi';

            if (preg_match($pattern, $block, $m)) {
                $value = trim($m[1], " \t\r\n*_`-");
                $incident[$field] = ($value === '') ? 'N/A' : $value;
            } else {
                $incident[$field] = 'N/A';
            }
        }

        /*
        |----------------------------------------------------------------------
        | FIX UNKNOWN / EMPTY ATTACK TYPE
        |----------------------------------------------------------------------
        */

        $at = strtolower(trim($incident['Attack Type']));
        if ($at === 'unknown' || $at === 'n/a' || $at === '') {
            $incident['Attack Type'] = detectAttackFallback($block . "\n" . $logs);
        }

        /*
        |----------------------------------------------------------------------
        | FIX UNKNOWN / EMPTY SOURCE IP
        |----------------------------------------------------------------------
        */

        $src = strtolower(trim($incident['Source']));
        if ($src === 'unknown' || $src === 'n/a' || $src === '') {
            $incident['Source'] = extractIP($block);
            if ($incident['Source'] === 'Unknown') {
                $incident['Source'] = extractIP($logs);
            }
        }

        /*
        |----------------------------------------------------------------------
        | NORMALIZE SEVERITY
        | Handles: "High", "HIGH", "High (8/10)", "high severity", etc.
        |----------------------------------------------------------------------
        */

        $validSeverities = ['Low', 'Medium', 'High', 'Critical'];

        preg_match('/\b(low|medium|high|critical)\b/i', $incident['Severity'], $sevMatch);
        $sev = isset($sevMatch[1])
            ? ucfirst(strtolower($sevMatch[1]))
            : 'Medium';

        if (!in_array($sev, $validSeverities)) { $sev = 'Medium'; }

        /*
        |----------------------------------------------------------------------
        | AUTO SEVERITY BOOST
        |----------------------------------------------------------------------
        */

        if (
            stripos($incident['Attack Type'], 'SQL')  !== false ||
            stripos($incident['Attack Type'], 'XSS')  !== false
        ) {
            if ($sev === 'Low') { $sev = 'Medium'; }
        }

        if (
            stripos($incident['Attack Type'], 'Remote Command') !== false ||
            stripos($incident['Attack Type'], 'Privilege')      !== false ||
            stripos($incident['Attack Type'], 'RCE')            !== false
        ) {
            if ($sev === 'Medium') { $sev = 'High'; }
        }

        $incident['Severity'] = $sev;

        /*
        |----------------------------------------------------------------------
        | CATEGORY TAG
        |----------------------------------------------------------------------
        */

        $incident['category'] = (
            stripos($incident['Attack Type'], 'unknown') !== false ||
            stripos($incident['Attack Type'], 'anomal')  !== false
        ) ? 'unknown' : 'known';

        /*
        |----------------------------------------------------------------------
        | CONFIDENCE — normalise to "NN%"
        |----------------------------------------------------------------------
        */

        preg_match('/(\d+)/', $incident['Confidence'], $cm);
        $incident['Confidence'] = isset($cm[1]) ? $cm[1] . '%' : '75%';

        $incidents[] = $incident;
    }

    return $incidents;
}