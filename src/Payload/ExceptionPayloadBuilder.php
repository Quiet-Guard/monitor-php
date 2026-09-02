<?php

namespace QuietGuard\Monitor\Payload;

use Throwable;

/**
 * Builds the platform-neutral ingestion payload from a Throwable.
 */
class ExceptionPayloadBuilder
{
    public function __construct(
        private readonly int $traceLimit = 0,
        private readonly ?string $release = null,
    ) {}

    /**
     * @param  array<string, mixed>  $context
     * @return array<string, mixed>
     */
    public function build(Throwable $e, array $context = []): array
    {
        return [
            'exception' => [
                'class' => $e::class,
                'message' => $e->getMessage(),
                'file' => $e->getFile(),
                'line' => $e->getLine(),
                'trace' => $this->trace($e),
            ],
            'context' => array_merge(
                array_filter(['release' => $this->release], static fn ($v) => $v !== null),
                $context,
            ),
        ];
    }

    /**
     * @return array<int, array<string, mixed>>
     */
    private function trace(Throwable $e): array
    {
        $frames = [];

        $trace = $this->traceLimit > 0
            ? array_slice($e->getTrace(), 0, $this->traceLimit)
            : $e->getTrace();

        foreach ($trace as $frame) {
            $frames[] = [
                'class' => $frame['class'] ?? null,
                'type' => $frame['type'] ?? null,
                'function' => $frame['function'] ?? null,
                'file' => $frame['file'] ?? null,
                'line' => $frame['line'] ?? null,
            ];
        }

        return $frames;
    }
}
