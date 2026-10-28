<?php

namespace QuietGuard\Monitor;

use Psr\Log\LoggerInterface;
use QuietGuard\Monitor\Http\HttpClient;
use QuietGuard\Monitor\Payload\ExceptionPayloadBuilder;
use QuietGuard\Monitor\Support\Cut;
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
        $this->builder = $builder ?? new ExceptionPayloadBuilder($config->traceLimit, $config->release, $config->codeSnippets);

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
        $payload['context'] = $this->scrubber->scrub(self::plain($payload['context']));
        $payload['exception']['trace'] = $this->scrubber->scrubSnippets($payload['exception']['trace'] ?? []);

        // Bornée APRÈS le masquage : masquer REMPLACE une valeur par une
        // étiquette plus longue, donc une charge coupée avant pouvait repasser
        // au-dessus de la limite du serveur et se faire refuser en silence,
        // exactement ce que la troncature existe pour empêcher. Et bornée
        // AVANT, mollement (Cut::before) : une coupe dure avant le masquage
        // laissait partir la moitié d'un jeton à cheval sur la limite.
        return $this->post('/api/v1/ingest', Cut::payload($this->redactor->redactAll(Cut::before($payload))), 'exception');
    }

    /**
     * @param  array<int, array<string, mixed>>  $logs
     */
    public function sendLogs(array $logs): bool
    {
        if ($logs === []) {
            return true;
        }

        foreach ($logs as $index => $log) {
            if (is_array($log['context'] ?? null)) {
                $logs[$index]['context'] = self::plain($log['context']);
            }
        }

        return $this->post('/api/v1/logs', Cut::payload($this->redactor->redactAll(Cut::before(
            ['logs' => $this->scrubber->scrub($logs)],
        ))), 'logs');
    }

    /**
     * The data json_encode would have sent, computed BEFORE masking: the
     * scrubber and the redactor walk arrays and strings only, so an object (a
     * DTO, a Collection) used to be expanded by the transport's json_encode,
     * after them, with its 'password' in clear.
     *
     * When the whole cannot be encoded (a jsonSerialize() that throws, a
     * depth past 512), each key is tried alone, so one bad value costs that
     * value and not the release, the environment or the request beside it.
     *
     * @param  array<array-key, mixed>  $data
     * @return array<array-key, mixed>
     */
    private static function plain(array $data, int $depth = 0): array
    {
        $whole = self::encodable($data);

        if ($whole !== null) {
            return $whole;
        }

        $plain = [];

        foreach ($data as $key => $value) {
            $alone = self::encodable([$value]);

            $plain[$key] = match (true) {
                $alone !== null => $alone[0] ?? null,
                is_array($value) => $depth < 16 ? self::plain($value, $depth + 1) : '[depth]',
                is_object($value) => $value::class,
                default => null,
            };
        }

        return $plain;
    }

    /**
     * @param  array<array-key, mixed>  $data
     * @return array<array-key, mixed>|null
     */
    private static function encodable(array $data): ?array
    {
        try {
            $json = json_encode($data, JSON_INVALID_UTF8_SUBSTITUTE | JSON_PARTIAL_OUTPUT_ON_ERROR);
        } catch (Throwable) {
            return null;
        }

        $decoded = $json === false ? null : json_decode($json, true);

        return is_array($decoded) ? $decoded : null;
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

        // Config a déjà normalisé l'adresse (barre finale, préfixe d'API,
        // valeur absente). Une seconde normalisation ici serait une seconde
        // définition de la même règle, donc celle qui diverge un jour.
        $url = $this->config->url.$path;

        try {
            $status = $this->http->postJson(
                $url,
                $this->config->key,
                $payload,
                $this->config->timeout,
            );

            if ($status >= 200 && $status < 300) {
                return true;
            }

            // A refusal the server can explain used to vanish here: CurlHttpClient
            // never throws, it returns 0, so the catch below was the only path
            // that ever said anything and it could not fire. A 401 on a mistyped
            // key, a 402 during dunning and a 403 on a plan gate were all one
            // silent false, in clients that have no console to print to.
            $this->logger?->warning("Monitor: {$kind} refused", [
                'status' => $status,
                'url' => $url,
            ]);

            return false;
        } catch (Throwable $e) {
            $this->logger?->warning("Monitor: failed to send {$kind}", [
                'error' => $e->getMessage(),
                'url' => $url,
            ]);

            return false;
        }
    }
}
