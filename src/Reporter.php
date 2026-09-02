<?php

namespace QuietGuard\Monitor;

use Psr\Log\LoggerInterface;
use QuietGuard\Monitor\Http\HttpClient;
use QuietGuard\Monitor\Payload\ExceptionPayloadBuilder;
use QuietGuard\Monitor\Support\Scrubber;
use QuietGuard\Monitor\Support\ValueRedactor;
use Throwable;

/**
 * The platform-neutral client. Adapters (Laravel, Symfony, WordPress) wire it to
 * the host's exception/logging hooks. Reporting never throws: monitoring must
 * not break the host application.
 */
class Reporter
{
    private readonly ExceptionPayloadBuilder $builder;

    private readonly ValueRedactor $redactor;

    public function __construct(
        private readonly Config $config,
        private readonly HttpClient $http,
        private readonly Scrubber $scrubber,
        ?ExceptionPayloadBuilder $builder = null,
        private readonly ?LoggerInterface $logger = null,
    ) {
        // Default to a builder wired from the Config, so release and traceLimit
        // set there apply without hand-constructing an ExceptionPayloadBuilder.
        $this->builder = $builder ?? new ExceptionPayloadBuilder($config->traceLimit, $config->release);

        // Value masking is the last thing that happens to a payload. Doing it
        // here rather than in each builder means a field added later cannot be
        // forgotten: whatever reaches the wire has been through it.
        $this->redactor = $config->redactor();
    }

    /**
     * @param  array<string, mixed>  $context
     */
    public function reportException(Throwable $e, array $context = []): bool
    {
        $payload = $this->builder->build($e, $context);
        $payload['context'] = $this->scrubber->scrub($payload['context']);

        return $this->post('/api/v1/ingest', $this->redactor->redactAll($payload), 'exception');
    }

    /**
     * @param  array<int, array<string, mixed>>  $logs
     */
    public function sendLogs(array $logs): bool
    {
        if ($logs === []) {
            return true;
        }

        return $this->post('/api/v1/logs', $this->redactor->redactAll(
            ['logs' => $this->scrubber->scrub($logs)],
        ), 'logs');
    }

    /**
     * @param  array<int, array<string, mixed>>  $packages
     */
    public function sendDependencies(array $packages): bool
    {
        if ($packages === []) {
            return false;
        }

        return $this->post('/api/v1/dependencies', ['packages' => $packages], 'dependencies');
    }

    /**
     * @param  array<string, mixed>  $payload
     */
    private function post(string $path, array $payload, string $kind): bool
    {
        if (! $this->config->isConfigured()) {
            return false;
        }

        try {
            $status = $this->http->postJson(
                rtrim($this->config->url, '/').$path,
                $this->config->key,
                $payload,
                $this->config->timeout,
            );

            return $status >= 200 && $status < 300;
        } catch (Throwable $e) {
            $this->logger?->warning("Monitor: failed to send {$kind}", ['error' => $e->getMessage()]);

            return false;
        }
    }
}
