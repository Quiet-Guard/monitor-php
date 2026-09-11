<?php

namespace QuietGuard\Monitor\Support;

/**
 * Masks sensitive values by key, recursively. Framework-agnostic.
 *
 * Matching is by lower-cased substring, so a configured "password" also masks
 * "user_password" and "PASSWORD_CONFIRMATION": derived key names must never
 * leak just because the exact spelling was not listed.
 */
class Scrubber
{
    public const MASK = '[scrubbed]';

    /** @var array<int, string> lower-cased needles to mask */
    private array $keys;

    /**
     * @param  array<int, string>  $keys
     */
    public function __construct(array $keys = [])
    {
        $this->keys = array_map('strtolower', $keys);
    }

    /**
     * @param  array<mixed>  $data
     * @return array<mixed>
     */
    public function scrub(array $data): array
    {
        foreach ($data as $key => $value) {
            if (is_string($key) && $this->matches(strtolower($key))) {
                $data[$key] = static::MASK;

                continue;
            }

            if (is_array($value)) {
                $data[$key] = $this->scrub($value);
            }
        }

        return $data;
    }

    /**
     * The words that name a secret in CODE, beyond the request keys: an
     * `$apiKey`, a `$signingKey`, a `withBasicAuth()`, a `$dsn` holding a
     * password. A false positive costs one line of context; the list is
     * broader than the request one for that reason.
     */
    public const LINE_NEEDLES = ['key', 'auth', 'credential', 'salt', 'private', 'dsn', 'bearer', 'sk_', 'pk_'];

    /**
     * Mask every source line that names a secret and gives it a value.
     *
     * A snippet is source code, and source code is where a hardcoded secret
     * lives: `$secret = 'correct horse battery';` six lines above a throw
     * would travel in clear while the request field of the same name is
     * masked. A line goes whole when an identifier containing a needle is
     * followed by a value: an assignment or key separator (`=`, `=>`, `:`), a
     * quoted name before a comma (`define('API_KEY', ...)`), or a call whose
     * first argument is a literal (`setApiKey('sk_live...')`). A line that
     * only USES the name (`Hash::check($password, ...)`, `csrf_token()`,
     * WordPress's `get_the_author()` against a list holding `auth`) carries no
     * value and stays: masking by bare substring made a WordPress snippet
     * unreadable. A literal that names none of the words still travels; the
     * documentation says so.
     *
     * @param  array<int, string>  $lines
     * @return array<int, string>
     */
    public function scrubLines(array $lines): array
    {
        return array_map(
            fn (string $line): string => $this->namesAValue($line) ? static::MASK : $line,
            $lines,
        );
    }

    private function namesAValue(string $line): bool
    {
        $lower = strtolower($line);

        foreach (array_unique(array_merge($this->keys, self::LINE_NEEDLES)) as $needle) {
            if ($needle === '' || ! str_contains($lower, $needle)) {
                continue;
            }

            // An assignment or key separator, a quoted name before a comma,
            // or a call whose first argument is a literal; never a bare
            // comma, or `Hash::check($secretGuess, $hash)` would go too.
            if (preg_match('/'.preg_quote($needle, '/').'\w*(?:[\'"]?\s*(?:=>|=|:)|[\'"]\s*,|\(\s*[\'"])/i', $line) === 1) {
                return true;
            }
        }

        return false;
    }

    /**
     * Apply scrubLines() to the snippet each stack frame may carry.
     *
     * @param  array<int, array<string, mixed>>  $frames
     * @return array<int, array<string, mixed>>
     */
    public function scrubSnippets(array $frames): array
    {
        foreach ($frames as $i => $frame) {
            if (is_array($frame) && isset($frame['code']['lines']) && is_array($frame['code']['lines'])) {
                $frames[$i]['code']['lines'] = $this->scrubLines(array_map('strval', $frame['code']['lines']));
            }
        }

        return $frames;
    }

    private function matches(string $key): bool
    {
        foreach ($this->keys as $needle) {
            if ($needle !== '' && str_contains($key, $needle)) {
                return true;
            }
        }

        return false;
    }
}
