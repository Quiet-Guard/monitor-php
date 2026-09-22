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

            if (is_string($value)) {
                $data[$key] = $this->scrubString($value);
            }
        }

        return $data;
    }

    /**
     * A value that is a JSON object, or a URL carrying a query string, holds
     * named values of its own, and the rule that masks a named value has to
     * reach them.
     *
     * Livewire is the case that forced it: `components.*.snapshot` is a JSON
     * STRING, so a password typed into a component sailed past a scrubber
     * that only descends into arrays. And a reset link carries its token and
     * its signature in the query, where no key ever named them.
     */
    private function scrubString(string $value): string
    {
        $trimmed = ltrim($value);

        if (str_starts_with($trimmed, '{') || str_starts_with($trimmed, '[')) {
            $decoded = json_decode($value, true, 512, JSON_BIGINT_AS_STRING);

            if (is_array($decoded)) {
                $scrubbed = $this->scrub($decoded);

                // Nothing inside named a secret: the value goes as it came,
                // byte for byte. Encoding it again is not neutral (`{}` comes
                // back `[]`, every accent grows into the six bytes of
                // `\u00e9`), and a French snapshot that triples can cross the
                // bound that drops a whole context. Masking must never be the
                // reason a report loses what it held.
                if ($scrubbed === $decoded) {
                    return $value;
                }

                $encoded = json_encode($scrubbed, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRESERVE_ZERO_FRACTION);

                // A value that held a secret and cannot be written back masked
                // (a literal past the float range decodes to INF, which
                // json_encode refuses) goes whole: handing it back as it came
                // would send the secret this very call just found.
                return $encoded === false ? static::MASK : $encoded;
            }
        }

        return $this->scrubUrl($value);
    }

    /**
     * Mask the named values of a URL's query string, and nothing else: the
     * path is what says where the application broke.
     */
    public function scrubUrl(string $url): string
    {
        if (! preg_match('#^https?://[^\s]+\?#i', $url)) {
            return $url;
        }

        [$base, $query] = explode('?', $url, 2);
        $fragment = '';

        if (str_contains($query, '#')) {
            [$query, $fragment] = explode('#', $query, 2);
            $fragment = '#'.$fragment;
        }

        $pairs = array_map(function (string $pair): string {
            [$name, $value] = array_pad(explode('=', $pair, 2), 2, null);

            if ($value === null || ! $this->matches(strtolower(rawurldecode($name)))) {
                return $pair;
            }

            return $name.'='.rawurlencode(self::MASK);
        }, explode('&', $query));

        return $base.'?'.implode('&', $pairs).$fragment;
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
