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

    /**
     * The server's own limits, by field. `context` is the number of encoded
     * bytes past which the server replaces a context by a marker
     * (IngestedContext::MAX_BYTES there), for an exception as for a log.
     */
    public const LIMITS = [
        'snippet_line' => 500,
        'message' => 8192,
        'class' => 255,
        'file' => 1024,
        'release' => 255,
        'context' => 65535,
    ];

    /**
     * How far past the limit soft() may go to reach a whitespace.
     */
    public const SLACK = 4096;

    /**
     * The marker the server writes in place of a context it refuses, kept
     * as the client's too so a reader sees one shape.
     */
    public const CONTEXT_MARKER = ['_truncated' => true];

    /**
     * Cut at the first whitespace at or past the limit, within SLACK
     * characters of it, and only then hard at limit plus slack.
     *
     * The cut that happens BEFORE masking. A value is masked by its shape,
     * and a shape is a run of characters with a minimum length: a token cut
     * in the middle by a hard cut at the limit is no longer a token, so its
     * first half, the half that carries the prefix, travelled in clear. Cut
     * on a whitespace instead, no one-line shape straddles the cut; the
     * hard cut after the limit, in redactor terms Cut::payload(), then falls
     * on a value that is already masked. The slack bounds what is read.
     */
    public static function soft(?string $value, int $limit): ?string
    {
        if ($value === null || mb_strlen($value) <= $limit) {
            return $value;
        }

        // Already cut once (by a builder, then again by Cut::before on the
        // way out): a second soft cut landed on the whitespace inside the
        // marker and wrote a second marker behind the first.
        if (str_ends_with($value, self::MARKER)) {
            return $value;
        }

        $window = mb_substr($value, $limit, self::SLACK);

        if (preg_match('/\s/u', $window, $m, PREG_OFFSET_CAPTURE) === 1) {
            $at = $limit + mb_strlen(substr($window, 0, $m[0][1]));
        } elseif (mb_strlen($value) <= $limit + self::SLACK) {
            // No whitespace to cut on, and the whole value is within the
            // slack: it goes whole, the hard cut after masking bounds it.
            return $value;
        } else {
            $at = $limit + self::SLACK;
        }

        return mb_substr($value, 0, $at).self::MARKER;
    }

    /**
     * Bound a payload BEFORE masking, without cutting through a value.
     *
     * Two things are bounded here. The free-text fields (an exception
     * message, a log message, a snippet line) are soft-cut at a whitespace
     * past their limit, so masking reads whole tokens and the hard cut of
     * payload() lands on masked text. And a context whose encoded size is
     * past what the server keeps (LIMITS['context']) is replaced by the same
     * marker the server would write, keeping the three keys the server reads
     * off it before replacing it: scanning several megabytes the server will
     * drop anyway costs the failing request for nothing, and replacing the
     * whole context cuts through no value at all.
     *
     * @param  array<string, mixed>  $payload
     * @return array<string, mixed>
     */
    public static function before(array $payload): array
    {
        if (isset($payload['exception']['message']) && is_string($payload['exception']['message'])) {
            $payload['exception']['message'] = self::soft($payload['exception']['message'], self::LIMITS['message']);
        }

        if (isset($payload['exception']['trace']) && is_array($payload['exception']['trace'])) {
            foreach ($payload['exception']['trace'] as $i => $frame) {
                if (! is_array($frame) || ! isset($frame['code']['lines']) || ! is_array($frame['code']['lines'])) {
                    continue;
                }

                foreach ($frame['code']['lines'] as $j => $line) {
                    if (is_string($line)) {
                        $payload['exception']['trace'][$i]['code']['lines'][$j] = self::soft($line, self::LIMITS['snippet_line']);
                    }
                }
            }
        }

        if (isset($payload['context']) && is_array($payload['context'])) {
            $payload['context'] = self::boundedContext($payload['context']);
        }

        if (isset($payload['logs']) && is_array($payload['logs'])) {
            foreach ($payload['logs'] as $i => $entry) {
                if (isset($entry['message']) && is_string($entry['message'])) {
                    $payload['logs'][$i]['message'] = self::soft($entry['message'], self::LIMITS['message']);
                }

                if (isset($entry['context']) && is_array($entry['context'])) {
                    $payload['logs'][$i]['context'] = self::boundedContext($entry['context']);
                }
            }
        }

        return $payload;
    }

    /**
     * The context as it is, or the marker with the three keys the server
     * reads before it replaces an oversized context.
     *
     * @param  array<array-key, mixed>  $context
     * @return array<array-key, mixed>
     */
    private static function boundedContext(array $context): array
    {
        $encoded = json_encode($context);

        if ($encoded !== false && strlen($encoded) <= self::LIMITS['context']) {
            return $context;
        }

        $kept = [];

        foreach (['environment', 'release', 'occurred_at', 'logged_at'] as $key) {
            if (isset($context[$key]) && is_scalar($context[$key])) {
                $kept[$key] = $context[$key];
            }
        }

        return $kept + self::CONTEXT_MARKER;
    }

    /**
     * Bound a whole ingestion payload, AFTER redaction and last before the wire.
     * The pass before redaction is before().
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
