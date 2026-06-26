<?php

namespace LaBoiteACode\Monitor\Http;

/**
 * Minimal transport contract so adapters can inject any client (PSR-18, Guzzle,
 * the framework HTTP client, …). Implementations must not throw.
 */
interface HttpClient
{
    /**
     * POST a JSON body with a Bearer token.
     *
     * @param  array<string, mixed>  $payload
     * @return int HTTP status code, or 0 on transport failure
     */
    public function postJson(string $url, string $token, array $payload, int $timeout): int;
}
