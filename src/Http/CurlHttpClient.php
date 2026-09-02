<?php

namespace QuietGuard\Monitor\Http;

/**
 * Dependency-free transport using ext-curl. Never throws.
 */
class CurlHttpClient implements HttpClient
{
    public function postJson(string $url, string $token, array $payload, int $timeout): int
    {
        $body = json_encode($payload);

        if ($body === false) {
            return 0;
        }

        $ch = curl_init($url);

        if ($ch === false) {
            return 0;
        }

        curl_setopt_array($ch, [
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => $body,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => $timeout,
            CURLOPT_HTTPHEADER => [
                'Content-Type: application/json',
                'Accept: application/json',
                'Authorization: Bearer '.$token,
            ],
        ]);

        curl_exec($ch);
        $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        curl_close($ch);

        return $status;
    }
}
