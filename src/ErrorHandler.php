<?php

namespace LaBoiteACode\Monitor;

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
        set_exception_handler(static function (Throwable $e) use ($reporter): void {
            $reporter->reportException($e);
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
