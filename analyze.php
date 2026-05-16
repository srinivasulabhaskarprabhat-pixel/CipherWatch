<?php

/*
|--------------------------------------------------------------------------
| analyze.php — Entry Point
| All files are in the same flat folder (htdocs/ai/)
|--------------------------------------------------------------------------
*/

require_once __DIR__ . '/cors.php';
require_once __DIR__ . '/helpers.php';
require_once __DIR__ . '/fallback_classifier.php';
require_once __DIR__ . '/local_scan.php';
require_once __DIR__ . '/ai_request.php';
require_once __DIR__ . '/incident_parser.php';

/*
|--------------------------------------------------------------------------
| READ INPUT
|--------------------------------------------------------------------------
*/

$data = json_decode(file_get_contents("php://input"), true);
$logs = trim($data["logs"] ?? "");

if (!$logs) {
    echo json_encode([
        "result"    => "No logs provided.",
        "incidents" => []
    ]);
    exit;
}

/*
|--------------------------------------------------------------------------
| LOCAL ANOMALY SCAN
|--------------------------------------------------------------------------
*/

$anomalyHints = localAnomalyScan($logs);

$anomalyContext = "";

if (!empty($anomalyHints)) {
    $anomalyContext .= "\n=== PRE-SCAN ANOMALIES ===\n";
    foreach ($anomalyHints as $hint) {
        $anomalyContext .= "- $hint\n";
    }
    $anomalyContext .= "=== END PRE-SCAN ===\n";
}

/*
|--------------------------------------------------------------------------
| AI ANALYSIS
|--------------------------------------------------------------------------
*/

$content = callAI($logs, $anomalyContext);

if ($content === null) {
    exit;
}

/*
|--------------------------------------------------------------------------
| PARSE + FILTER INCIDENTS
|--------------------------------------------------------------------------
*/

$incidents = parseIncidents($content, $logs);

$incidents = array_filter($incidents, function ($inc) {
    $conf      = intval(preg_replace('/[^0-9]/', '', $inc['Confidence'] ?? '0'));
    $isUnknown = (
        stripos($inc['Attack Type'], 'unknown') !== false ||
        stripos($inc['Attack Type'], 'anomal')  !== false
    );
    return $isUnknown ? ($conf >= 60) : ($conf >= 70);
});

$incidents = array_values($incidents);

/*
|--------------------------------------------------------------------------
| KNOWN VS UNKNOWN SPLIT
|--------------------------------------------------------------------------
*/

$known = array_values(array_filter($incidents, function ($i) {
    return stripos($i['Attack Type'], 'unknown') === false &&
           stripos($i['Attack Type'], 'anomal')  === false;
}));

$unknown = array_values(array_filter($incidents, function ($i) {
    return stripos($i['Attack Type'], 'unknown') !== false ||
           stripos($i['Attack Type'], 'anomal')  !== false;
}));

/*
|--------------------------------------------------------------------------
| FINAL RESPONSE
|--------------------------------------------------------------------------
*/

echo json_encode([
    "result"            => $content,
    "incidents"         => $incidents,
    "known_incidents"   => $known,
    "unknown_incidents" => $unknown,
    "anomaly_hints"     => $anomalyHints,
    "total"             => count($incidents),
    "total_known"       => count($known),
    "total_unknown"     => count($unknown)
], JSON_PRETTY_PRINT);
