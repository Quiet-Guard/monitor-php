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

    /** Application frames past this many carry no snippet: the budget of a report, not of a file. */
    public const MAX_SNIPPET_FRAMES = 10;

    public function __construct(
        private readonly int $traceLimit = 0,
        private readonly ?string $release = null,
        private readonly bool $codeSnippets = true,
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

    private function trace(Throwable $e): array
    {
        return self::frames($e, $this->traceLimit, $this->codeSnippets);
    }

    /**
     * The throw site first, then PHP's own trace.
     *
     * getTrace() starts at the caller of the throwing function, so the line
     * that raised the exception is not in it; it is the exception's own file
     * and line, and the dashboard shows it as frame zero the way Laravel's
     * exception page does. The trace limit counts that frame, so `1` is the
     * site alone. Application frames carry a source snippet (see
     * SourceSnippet) while `$codeSnippets` is on; dependencies never do.
     * Static, so the Laravel SDK's builder shares it rather than a copy.
     *
     * @return array<int, array<string, mixed>>
     */
    public static function frames(Throwable $e, int $traceLimit = 0, bool $codeSnippets = true): array
    {
        $site = [
            'class' => null,
            'type' => null,
            'function' => null,
            'file' => $e->getFile(),
            'line' => $e->getLine(),
        ];

        $trace = $traceLimit > 0
            ? array_slice($e->getTrace(), 0, max(0, $traceLimit - 1))
            : $e->getTrace();

        $frames = [];
        $budget = $codeSnippets ? self::MAX_SNIPPET_FRAMES : 0;

        foreach ([$site, ...$trace] as $frame) {
            $shaped = [
                'class' => $frame['class'] ?? null,
                'type' => $frame['type'] ?? null,
                'function' => $frame['function'] ?? null,
                'file' => $frame['file'] ?? null,
                'line' => $frame['line'] ?? null,
            ];

            if ($budget > 0) {
                $snippet = SourceSnippet::around(
                    is_string($shaped['file']) ? $shaped['file'] : null,
                    is_int($shaped['line']) ? $shaped['line'] : null,
                );

                if ($snippet !== null) {
                    $shaped['code'] = $snippet;
                    $budget--;
                }
            }

            $frames[] = $shaped;
        }

        return $frames;
    }
}
