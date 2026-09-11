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

    /** The server's own limits, by field. */
    public const LIMITS = [
        'snippet_line' => 500,
        'message' => 8192,
        'class' => 255,
        'file' => 1024,
        'release' => 255,
    ];

    /**
     * Bound a whole ingestion payload, AFTER redaction and last before the wire.
     *
     * Cutting in the payload builder alone was not enough, and the case that
     * proves it is the one the redactor exists for: masking REPLACES a value
     * with a longer label, `[redacted:phone]` being sixteen characters where a
     * French number is ten. A message of phone numbers cut to 8192 came back
     * out of redactAll() at over twelve thousand and was refused by the same
     * silent 422 the truncation was added to stop.
     *
     * So the bound has to be the last thing that touches the payload, for the
     * same reason the redactor is: whatever happens after it is unbounded by
     * definition. The builder keeps its own pass, which costs nothing on an
     * already short string and still protects a caller who builds a payload
     * without going through a reporter.
     *
     * @param  array<string, mixed>  $payload
     * @return array<string, mixed>
     */
    public static function payload(array $payload): array
    {
        foreach (['class', 'message', 'file'] as $field) {
            if (isset($payload['exception'][$field]) && is_string($payload['exception'][$field])) {
                $payload['exception'][$field] = self::to($payload['exception'][$field], self::LIMITS[$field]);
            }
        }

        if (isset($payload['context']['release']) && is_string($payload['context']['release'])) {
            $payload['context']['release'] = self::to($payload['context']['release'], self::LIMITS['release']);
        }

        // Snippet lines are cut when read, then redaction LENGTHENS them (a
        // mask is longer than a short address), and the server refuses one
        // over the bound with the same silent 422 this pass exists to prevent.
        if (isset($payload['exception']['trace']) && is_array($payload['exception']['trace'])) {
            foreach ($payload['exception']['trace'] as $i => $frame) {
                if (! is_array($frame) || ! isset($frame['code']['lines']) || ! is_array($frame['code']['lines'])) {
                    continue;
                }

                foreach ($frame['code']['lines'] as $j => $line) {
                    if (is_string($line)) {
                        $payload['exception']['trace'][$i]['code']['lines'][$j] = self::to($line, self::LIMITS['snippet_line']);
                    }
                }
            }
        }

        if (isset($payload['logs']) && is_array($payload['logs'])) {
            foreach ($payload['logs'] as $i => $entry) {
                if (isset($entry['message']) && is_string($entry['message'])) {
                    $payload['logs'][$i]['message'] = self::to($entry['message'], self::LIMITS['message']);
                }
            }
        }

        return $payload;
    }
}
