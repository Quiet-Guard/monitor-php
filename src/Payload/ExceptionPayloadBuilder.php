<?php

namespace QuietGuard\Monitor\Payload;

use QuietGuard\Monitor\Support\Cut;
use Throwable;

/**
 * Builds the platform-neutral ingestion payload from a Throwable.
 */
class ExceptionPayloadBuilder
{
    /** The server's own limits, enforced here so a report is never lost to them. See Cut. */
    private const LIMITS = [
        'message' => 8192,
        'class' => 255,
        'file' => 1024,
        'release' => 255,
    ];

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
                'class' => Cut::to($e::class, self::LIMITS['class']),
                'message' => Cut::to($e->getMessage(), self::LIMITS['message']),
                'file' => Cut::to($e->getFile(), self::LIMITS['file']),
                'line' => $e->getLine(),
                'trace' => $this->trace($e),
            ],
            'context' => array_merge(
                array_filter(
                    ['release' => Cut::to($this->release, self::LIMITS['release'])],
                    static fn ($v) => $v !== null,
                ),
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
