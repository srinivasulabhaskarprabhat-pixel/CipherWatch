<?php

/*
|--------------------------------------------------------------------------
| php/fallback_classifier.php
| Rule-based attack classifier used when AI returns "Unknown" / "N/A"
|--------------------------------------------------------------------------
*/

function detectAttackFallback(string $text): string
{
    $text = strtolower($text);

    // SQL Injection
    if (
        preg_match('/union\s+select/i',      $text) ||
        preg_match('/or\s+1=1/i',            $text) ||
        preg_match('/information_schema/i',  $text) ||
        preg_match('/sleep\(/i',             $text) ||
        preg_match('/benchmark\(/i',         $text)
    ) {
        return "SQL Injection";
    }

    // XSS
    if (
        preg_match('/<script>/i',  $text) ||
        preg_match('/onerror=/i',  $text) ||
        preg_match('/alert\(/i',   $text)
    ) {
        return "Cross-Site Scripting (XSS)";
    }

    // Path Traversal
    if (
        preg_match('/\.\.\//',       $text) ||
        preg_match('/etc\/passwd/i', $text)
    ) {
        return "Path Traversal";
    }

    // Remote Command Execution
    if (
        preg_match('/powershell/i', $text) ||
        preg_match('/cmd\.exe/i',   $text) ||
        preg_match('/wget/i',       $text) ||
        preg_match('/curl/i',       $text)
    ) {
        return "Remote Command Execution";
    }

    // Brute Force (fallback — single-line pattern only; full detection is in local_scan.php)
    if (
        preg_match('/failed password/i', $text) ||
        preg_match('/invalid user/i',    $text)
    ) {
        return "Brute Force Attack";
    }

    // Port Scanning
    if (
        preg_match('/nmap/i',    $text) ||
        preg_match('/masscan/i', $text)
    ) {
        return "Port Scanning";
    }

    // DNS Tunneling
    if (
        preg_match('/query\[a\]/i',     $text) &&
        preg_match('/[a-z0-9]{20,}/i',  $text)
    ) {
        return "DNS Tunneling";
    }

    return "Unknown/Anomalous Activity";
}
