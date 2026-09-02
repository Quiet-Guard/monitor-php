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
    public static function register(Reporter $reporter): void
    {
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

        set_error_handler(static function (int $severity, string $message, string $file, int $line) use ($reporter): bool {
            if (! (error_reporting() & $severity)) {
                return false; // respect @-suppression / error_reporting level
            }

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
