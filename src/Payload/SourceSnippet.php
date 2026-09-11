<?php

namespace QuietGuard\Monitor\Payload;

use QuietGuard\Monitor\Support\Cut;

/**
 * A few lines of the application's own source around a stack frame.
 *
 * The dashboard shows the trace the way Laravel's exception page does, with
 * the failing line in its context, and that context can only come from the
 * machine that ran the code. Dependencies never carry one: their source is
 * public, identical on every install, and the reader came for their own
 * code. Reading is bounded (file size, line length, a window of a few lines)
 * and every failure answers null, because a snippet is decoration and a
 * report must never be lost to it.
 */
final class SourceSnippet
{
    /** Lines kept on each side of the frame's line. */
    public const CONTEXT_LINES = 5;

    /** The server refuses a longer line; cutting here keeps the report accepted. */
    public const MAX_LINE_LENGTH = 500;

    /** A source file larger than this is generated or vendored; not worth a read per exception. */
    public const MAX_FILE_BYTES = 2_097_152;

    /**
     * @return array{start: int, lines: array<int, string>}|null
     */
    public static function around(?string $file, ?int $line, int $context = self::CONTEXT_LINES): ?array
    {
        if ($file === null || $file === '' || $line === null || $line < 1 || $context < 0) {
            return null;
        }

        if (self::isExcluded($file) || ! is_file($file) || ! is_readable($file)) {
            return null;
        }

        $size = @filesize($file);

        if ($size === false || $size > self::MAX_FILE_BYTES) {
            return null;
        }

        $start = max(1, $line - $context);
        $end = $line + $context;
        $lines = [];
        $number = 0;

        try {
            $handle = @fopen($file, 'rb');

            if ($handle === false) {
                return null;
            }

            while (($raw = fgets($handle)) !== false) {
                $number++;

                if ($number < $start) {
                    continue;
                }

                if ($number > $end) {
                    break;
                }

                $lines[] = Cut::to(rtrim($raw, "\r\n"), self::MAX_LINE_LENGTH) ?? '';
            }

            fclose($handle);
        } catch (\Throwable) {
            return null;
        }

        // The line is past the end of the file: the source on disk is not the
        // source that ran (a deploy in between), and a window on the wrong
        // code is worse than none.
        if ($number < $line) {
            return null;
        }

        return ['start' => $start, 'lines' => $lines];
    }

    public static function isVendor(string $file): bool
    {
        return str_contains(str_replace('\\', '/', $file), '/vendor/');
    }

    /**
     * Dependencies, WordPress core, and the files that ARE the configuration:
     * a deprecation raised on a wp-config.php line would ship the database
     * host and the salts as its context.
     */
    public static function isExcluded(string $file): bool
    {
        $normalized = str_replace('\\', '/', $file);
        $basename = strtolower(basename($normalized));

        if (in_array($basename, ['wp-config.php', 'wp-config-sample.php', '.env'], true) || str_starts_with($basename, '.env.')) {
            return true;
        }

        foreach (['/vendor/', '/wp-includes/', '/wp-admin/', '/node_modules/'] as $segment) {
            if (str_contains($normalized, $segment)) {
                return true;
            }
        }

        return false;
    }
}
