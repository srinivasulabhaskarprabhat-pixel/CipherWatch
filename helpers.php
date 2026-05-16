<?php

/*
|--------------------------------------------------------------------------
| php/helpers.php
| Shared utility functions: IP extraction, Shannon entropy
|--------------------------------------------------------------------------
*/

/*
|--------------------------------------------------------------------------
| EXTRACT FIRST IP FROM TEXT
|--------------------------------------------------------------------------
*/

function extractIP(string $text): string
{
    if (preg_match('/\b(\d{1,3}(?:\.\d{1,3}){3})\b/', $text, $m)) {
        return $m[1];
    }
    return "Unknown";
}

/*
|--------------------------------------------------------------------------
| SHANNON ENTROPY — Detects high-entropy encoded payloads
|--------------------------------------------------------------------------
*/

function shannonEntropy(string $string): float
{
    $h   = 0;
    $len = strlen($string);

    if ($len === 0) {
        return 0;
    }

    foreach (count_chars($string, 1) as $v) {
        $p  = $v / $len;
        $h -= $p * log($p, 2);
    }

    return $h;
}
