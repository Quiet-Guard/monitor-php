<?php

namespace QuietGuard\Monitor\Support;

/**
 * One definition of "trim this to the length the server accepts".
 *
 * The ingestion endpoint validates message at 8192, class at 255, file at 1024
 * and release at 255, and answers 422 on any of them. No client truncated
 * anything and no client read the 422, so the reports a customer most wants
 * were precisely the ones that vanished: a QueryException carries the whole SQL
 * and its bindings in its message, and an exception from an anonymous class has
 * the absolute file path inside its class NAME, which on a release directory is
 * most of the 255 by itself.
 *
 * Truncating is lossy and it is the right answer: the first 8192 characters of
 * a query, marked as cut, are worth incomparably more than a silent drop.
 *
 * Written once here rather than in each of the two payload builders, because
 * the two of them agreeing today is not the same as them agreeing tomorrow.
 */
final class Cut
{
    public const MARKER = '… [truncated]';

    /**
     * Cut on CHARACTERS, never on bytes: substr() splits a multi-byte character
     * and produces a payload the server rejects as malformed UTF-8, which trades
     * one silent loss for another.
     */
    public static function to(?string $value, int $limit): ?string
    {
        if ($value === null || mb_strlen($value) <= $limit) {
            return $value;
        }

        return mb_substr($value, 0, $limit - mb_strlen(self::MARKER)).self::MARKER;
    }
}
