<?php

namespace QuietGuard\Monitor;

use ErrorException;
use Throwable;

/**
 * Registers global PHP handlers for plain-PHP / WordPress hosts that have no
 * framework exception pipeline. Frameworks (Laravel, Symfony) use their own
 * hooks instead and should NOT call this.
 */
class ErrorHandler
{
    /**
     * Severities worth an HTTP round trip by default.
     *
     * NOT every severity PHP reports. The handler used to forward all of them,
     * one SYNCHRONOUS POST each, with no floor, no de-duplication and no cap:
     * a single E_WARNING inside a loop over five hundred rows was five hundred
     * POSTs in one page load. On WordPress, where a warning from any theme or
     * plugin lands here, that reads to the visitor as an outage and burns a
     * free plan's monthly events in a day.
     *
     * The true fatals are absent on purpose: PHP does not call a user error
     * handler for E_ERROR, E_PARSE, E_CORE_ERROR or E_COMPILE_ERROR, and the
     * shutdown function below is what catches those. What is left here is the
     * pair a host actually raises and means: a userland fatal, and a type error
     * that PHP let through.
     */
    public const DEFAULT_SEVERITIES = E_USER_ERROR | E_RECOVERABLE_ERROR;

    /** How many errors one request may report before the rest are dropped. */
    public const DEFAULT_MAX_PER_REQUEST = 20;

    /**
     * @param  int|null  $severities  bitmask of severities to report; null takes DEFAULT_SEVERITIES.
     *                                Pass E_ALL to restore the old behaviour, at the cost described above.
     * @param  int  $maxPerRequest  a cap that applies whatever the mask, because a mask cannot see a loop.
     */
    public static function register(
        Reporter $reporter,
        ?int $severities = null,
        int $maxPerRequest = self::DEFAULT_MAX_PER_REQUEST,
    ): void {
        $severities ??= self::DEFAULT_SEVERITIES;
        $reported = 0;
        $seen = [];
        $previous = null;
        $previous = set_exception_handler(static function (Throwable $e) use ($reporter, &$previous): void {
            $reporter->reportException($e);

            if ($previous !== null) {
                ($previous)($e);

                return;
            }

            // A user exception handler suppresses PHP's default uncaught-exception
            // report; keep the local error log as the host's record of the crash.
            error_log(sprintf(
                'Uncaught %s: %s in %s:%d%sStack trace:%s%s',
                $e::class,
                $e->getMessage(),
                $e->getFile(),
                $e->getLine(),
                PHP_EOL,
                PHP_EOL,
                $e->getTraceAsString(),
            ));
        });

        set_error_handler(static function (int $severity, string $message, string $file, int $line) use (
            $reporter, $severities, $maxPerRequest, &$reported, &$seen
        ): bool {
            if (! (error_reporting() & $severity)) {
                return false; // respect @-suppression / error_reporting level
            }

            if (! ($severities & $severity)) {
                return false; // below the floor; still PHP's to handle
            }

            // One report per site per request. The same warning raised on the
            // same line a hundred times is one fact, and the hundred POSTs are
            // the host application's latency, not ours to spend.
            $site = $file.':'.$line.':'.$severity;

            if (isset($seen[$site]) || $reported >= $maxPerRequest) {
                return false;
            }

            $seen[$site] = true;
            $reported++;

            $reporter->reportException(new ErrorException($message, 0, $severity, $file, $line));

            return false; // let PHP's normal handler run too
        });

        register_shutdown_function(static function () use ($reporter): void {
            $error = error_get_last();
            $fatal = [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR];

            if ($error !== null && in_array($error['type'], $fatal, true)) {
                $reporter->reportException(
                    new ErrorException($error['message'], 0, $error['type'], $error['file'], $error['line']),
                );
            }
        });
    }
}
