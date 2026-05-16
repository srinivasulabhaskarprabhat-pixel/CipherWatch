<?php

/*
|--------------------------------------------------------------------------
| php/ai_request.php
| Builds and sends the prompt to OpenRouter, returns cleaned text content.
| Returns null on failure (and emits a JSON error response itself).
|--------------------------------------------------------------------------
*/

function callAI(string $logs, string $anomalyContext): ?string
{
    /*
    |--------------------------------------------------------------------------
    | API KEY
    |--------------------------------------------------------------------------
    */

    $api_key = "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";

    /*
    |--------------------------------------------------------------------------
    | SYSTEM PROMPT
    |--------------------------------------------------------------------------
    */

    $system_prompt = <<<'PROMPT'
You are an elite SOC analyst.

You MUST:
- Detect SQL Injection
- Detect XSS
- Detect RCE
- Detect brute force
- Detect port scanning
- Detect DNS tunneling
- Detect privilege escalation
- Detect malware indicators
- Detect suspicious process execution
- Detect unknown/anomalous activity

IMPORTANT:
- NEVER return only "Unknown"
- If evidence exists, classify using the closest known attack category
- Always extract Source IPs
- Always provide confidence levels
- Always explain evidence

STRICT OUTPUT FORMAT:

Incident:
Attack Type:
Severity:
Confidence:
Source:
Target:
Description:
Evidence:
PROMPT;

    /*
    |--------------------------------------------------------------------------
    | USER MESSAGE
    |--------------------------------------------------------------------------
    */

    $userMessage  = "Analyze these logs carefully.\n";
    $userMessage .= "Detect known attacks and unknown anomalies.\n";
    $userMessage .= $anomalyContext;
    $userMessage .= "\nLOGS:\n" . $logs;

    /*
    |--------------------------------------------------------------------------
    | REQUEST PAYLOAD
    |--------------------------------------------------------------------------
    */

    $request = [
        "model"       => "meta-llama/llama-3.1-8b-instruct",
        "messages"    => [
            ["role" => "system", "content" => $system_prompt],
            ["role" => "user",   "content" => $userMessage]
        ],
        "temperature" => 0.10,
        "max_tokens"  => 4000,
        "top_p"       => 0.9
    ];

    /*
    |--------------------------------------------------------------------------
    | CURL
    |--------------------------------------------------------------------------
    */

    $ch = curl_init("https://openrouter.ai/api/v1/chat/completions");

    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST,           true);
    curl_setopt($ch, CURLOPT_TIMEOUT,        60);
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        "Authorization: Bearer $api_key",
        "Content-Type: application/json",
        "HTTP-Referer: http://localhost",
        "X-Title: SOC Console"
    ]);
    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($request));

    $response   = curl_exec($ch);
    $curl_error = curl_error($ch);
    curl_close($ch);

    if ($curl_error) {
        echo json_encode(["result" => "Connection error: $curl_error", "incidents" => []]);
        return null;
    }

    $res = json_decode($response, true);

    if (!$res || !isset($res["choices"][0]["message"]["content"])) {
        $err = $res["error"]["message"] ?? $response;
        echo json_encode(["result" => "API error: $err", "incidents" => []]);
        return null;
    }

    /*
    |--------------------------------------------------------------------------
    | CLEAN RESPONSE
    |--------------------------------------------------------------------------
    */

    $content = trim($res["choices"][0]["message"]["content"]);
    $content = preg_replace('/```[a-z]*\n?/i', '', $content);
    $content = str_replace('```', '', $content);
    $content = trim($content);

    return $content;
}
