<?php

namespace QuietGuard\Monitor\Support;

/**
 * Masks sensitive values by key, recursively. Framework-agnostic.
 *
 * Matching is by lower-cased substring, so a configured "password" also masks
 * "user_password" and "PASSWORD_CONFIRMATION": derived key names must never
 * leak just because the exact spelling was not listed. For the same reason a
 * hyphen and an underscore are one character: Symfony names every header
 * lower-cased with hyphens, so the password of a Basic auth request arrives as
 * "php-auth-pw" and an API key header as "x-api-key", while the lists write
 * "php_auth_pw" and "api_key". And a configured name with a separator inside
 * it is also found in a name written with none: Supabase and Kong send their
 * key as "apikey", a form field is "apiKey" (see $compactNames).
 *
 * Two kinds of string value hold secrets of their own, and the scrubber opens
 * both: a JSON object or array written as a string (Livewire's snapshot) is
 * decoded and masked by key like any array, and a string that starts with an
 * absolute http(s) URL has its query string masked by name, its token-shaped
 * path segments masked outright and the password of its userinfo masked (see
 * scrubUrl()); a string that starts with an address of any other scheme, a
 * DSN, has the password of its userinfo masked and nothing else.
 */
class Scrubber
{
    public const MASK = '[scrubbed]';

    /**
     * A path segment of forty letters or digits in a row: a token far more
     * often than an identifier.
     */
    private const PATH_TOKEN = '/^[A-Za-z0-9]{40,}$/';

    /**
     * The configured needles as names (see name()): what a key and a
     * query-string name are matched with.
     *
     * @var array<int, string>
     */
    private array $names;

    /**
     * The configured needles that carry a separator INSIDE them, written
     * with none (compactName()): `api_key` is also looked for as `apikey` in
     * a name stripped of its own hyphens and underscores, so `apikey`,
     * `apiKey`, `x-apikey` and `X-API-KEY` all match it.
     *
     * Only an interior separator is dropped. A needle that starts or ends
     * with one keeps its spelling, since without it the needle is an
     * ordinary word: WordPress's `db_` would become `db` and mask `feedback`.
     * A needle with no separator at all has nothing to drop and matches as
     * it always did.
     *
     * @var array<int, string>
     */
    private array $compactNames;

    /**
     * What a source line is read with (namesAValue()): each configured needle
     * and each line word, as written and in its other spelling
     * (otherSpelling()).
     *
     * The line itself is never rewritten: read with a hyphen as an
     * underscore, ordinary code goes too, such as
     * `->header('Referrer-Policy', ...)` against a list holding `referrer`.
     * The needle is what gets its other spelling, and only a hyphen or an
     * underscore between two letters or digits is swapped: that catches a
     * hardcoded `'php-auth-pw' => ...` under `php_auth_pw`. A needle that
     * starts or ends with a separator keeps its one spelling, since its other
     * one is the start or the end of an ordinary word: WordPress's `db_`
     * would read `'db-new'`, the line word `sk_` would read `'disk-usage'`.
     * The cost that remains is accepted: `logged_in` also reads `logged-in`,
     * so a line such as `array('logged-in', ...)` goes.
     *
     * @var array<int, string>
     */
    private array $lineNeedles;

    /**
     * @param  array<int, string>  $keys
     */
    public function __construct(array $keys = [])
    {
        $keys = array_map('strtolower', $keys);
        $needles = array_merge($keys, self::LINE_NEEDLES);

        $this->names = array_map(self::name(...), $keys);
        $this->compactNames = array_values(array_filter(array_map(self::compactName(...), $keys)));
        $this->lineNeedles = array_values(array_unique(array_merge(
            $needles,
            array_map(self::otherSpelling(...), $needles),
        )));
    }

    /**
     * @param  array<mixed>  $data
     * @return array<mixed>
     */
    public function scrub(array $data): array
    {
        foreach ($data as $key => $value) {
            if (is_string($key) && $this->matches(strtolower($key))) {
                $data[$key] = self::MASK;

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
     * A value that is a JSON object, or that starts with a URL, holds named
     * values of its own, and the rule that masks a named value has to reach
     * them.
     *
     * Livewire is the case that forced it: `components.*.snapshot` is a JSON
     * STRING, so a password typed into a component sailed past a scrubber
     * that only descends into arrays. And a reset link carries its token and
     * its signature in the query or in the path, where no key ever named
     * them.
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
                return $encoded === false ? self::MASK : $encoded;
            }

            // JSON the decoder refuses cannot be masked key by key, and handing
            // it back whole sends every secret it names. A client that masks
            // values by shape over the whole payload is how it happens: a
            // Livewire snapshot carrying a sixteen-digit timestamp that passes
            // Luhn comes out with `[redacted:card]` where a number was, which is
            // no longer JSON, the password beside it included. When a quoted
            // name followed by `:` matches, the value goes whole; text that
            // merely opens with a bracket names nothing and stays.
            if ($this->namesASecretKey($value)) {
                return self::MASK;
            }
        }

        return $this->scrubUrl($value);
    }

    /**
     * Whether text that opens like JSON holds a quoted name followed by a
     * colon (`"password":`) that matches, compared as a key is (matches()).
     *
     * One pass from left to right, string literal after string literal, the
     * way a decoder reads them: a `\` escapes the character after it, the
     * literal is decoded to read its name as the decoder would (`\u0077` is
     * `w`), and only a literal followed by optional whitespace and a `:` is a
     * name. Never a regular expression: the value is whatever a visitor
     * posted, unbounded on the client and read before the server's bound,
     * and a pattern that retries from every quote took seconds on a few
     * hundred kilobytes of escaped quotes, a worker per report.
     *
     * Then a second reading that pairs nothing (namesASecretKeyIgnoringEscapes()),
     * since text broken by a stray quote defeats the first.
     */
    private function namesASecretKey(string $value): bool
    {
        return $this->namesASecretKeyAsDecoded($value) || $this->namesASecretKeyIgnoringEscapes($value);
    }

    /**
     * The first reading of namesASecretKey(): literals paired as a decoder
     * pairs them.
     */
    private function namesASecretKeyAsDecoded(string $value): bool
    {
        $length = strlen($value);
        $offset = 0;

        while (($open = strpos($value, '"', $offset)) !== false) {
            $end = $open + 1;

            while (true) {
                $end += strcspn($value, '"\\', $end);

                if ($end >= $length) {
                    // A literal that never closes: nothing after it is a name.
                    return false;
                }

                if ($value[$end] === '"') {
                    break;
                }

                // A backslash: the character after it is part of the literal.
                $end += 2;

                if ($end >= $length) {
                    return false;
                }
            }

            $next = $end + 1;
            $next += strspn($value, " \t\n\r", $next);

            if ($next < $length && $value[$next] === ':') {
                $raw = substr($value, $open + 1, $end - $open - 1);
                // Only an escape makes the decoded name differ from the raw one.
                $name = str_contains($raw, '\\') ? json_decode('"'.$raw.'"') : $raw;

                if ($raw !== '' && $this->matches(strtolower(is_string($name) ? $name : $raw))) {
                    return true;
                }
            }

            $offset = $end + 1;
        }

        return false;
    }

    /**
     * The second reading of namesASecretKey(): every `"name":` whose name
     * holds no quote and no backslash, wherever it sits, paired with nothing
     * before it.
     *
     * The first reading pairs quotes as a decoder would, and that is its
     * weakness on text that is broken precisely because a quote went
     * unescaped: `{"a":"x"y", "password":"z"}` or a value cut short before its
     * closing quote shifts every pair after it, and the `"password":` further
     * on reads as the inside of a value. This one looks for the shape alone.
     * Possessive, anchored on a quote and restarted from the quote that
     * closed the previous name, so every character is read a bounded number
     * of times: linear, as the first reading is.
     */
    private function namesASecretKeyIgnoringEscapes(string $value): bool
    {
        $offset = 0;

        while (preg_match('/"([^"\\\\]*+)"\s*+:/', $value, $found, PREG_OFFSET_CAPTURE, $offset) === 1) {
            // No backslash can sit in the name, so there is nothing to
            // decode: the name reads as it is written.
            [$name, $start] = $found[1];

            if ($name !== '' && $this->matches(strtolower($name))) {
                return true;
            }

            // Restart on the quote that closed this name: it may open the next.
            $offset = $start + strlen($name);
        }

        return false;
    }

    /**
     * Mask what an absolute http(s) URL at the start of a string carries: the
     * values of its query string whose name matches the key list, and every
     * path segment shaped like a token.
     *
     * The path segment is the case the query rule cannot see: Laravel's own
     * reset link (Breeze, Fortify, Jetstream) puts its token in the PATH,
     * `/reset-password/{token}`, and so does any link that is its own
     * credential, an invitation or a status page. Forty letters or digits in
     * a row is that shape; a number, a slug, a UUID (hyphens) or a ULID (26
     * characters) is not, and stays, since the path is what says where the
     * application broke.
     *
     * Only the leading URL is read as an address, after any leading
     * whitespace, and it ends at the first whitespace: the text after it is
     * handed back as it came, so a log message keeps its sentence, and a
     * path further into that text is not looked at. One thing in that text
     * is still masked, a pair opened by `&`, `?` or `#` whose name matches
     * (scrubPairs()): a URL written by hand with an unencoded space
     * (`?q=hello world&token=abc`) pushes the rest of its own query there.
     *
     * The scheme, the host and the port travel as they came, and so does the
     * user of a userinfo; its password does not (`user:%5Bscrubbed%5D@`),
     * since a URL typed into a form field or a webhook setting carries it
     * there. A string that starts with an address of another scheme, a DSN
     * such as `mysql://root:secret@db/app`, has that password masked and
     * nothing else (scrubOtherAddress()). A relative address
     * (`/reset?token=...`) is not reached at all. A fragment is never read as
     * path, but its `name=value` pairs are, since that is where a hash router
     * writes its query (`#/reset?token=abc`) and an OAuth redirect its token
     * (`#access_token=...`).
     */
    public function scrubUrl(string $url): string
    {
        if (preg_match('~^(\s*)(https?://\S+)(.*)$~is', $url, $parts) !== 1) {
            return $this->scrubOtherAddress($url);
        }

        [, $lead, $address, $text] = $parts;

        return $lead.$this->scrubAddress($address).$this->scrubPairs($text);
    }

    private function scrubAddress(string $address): string
    {
        [$base, $query] = array_pad(explode('?', $address, 2), 2, null);
        $base = $this->scrubPath($base);

        return $query === null ? $base : $base.'?'.$this->scrubQuery($query);
    }

    /**
     * A query string, its fragment included, with the value of every pair
     * whose name matches masked. The rule of names, for an address of any
     * scheme: a DSN carries its options there, a password among them
     * (Predis reads `tcp://127.0.0.1:6379?password=...`).
     */
    private function scrubQuery(string $query): string
    {
        $fragment = '';

        if (str_contains($query, '#')) {
            [$query, $fragment] = explode('#', $query, 2);
            $fragment = $this->scrubPairs('#'.$fragment);
        }

        $pairs = array_map(function (string $pair): string {
            [$name, $value] = array_pad(explode('=', $pair, 2), 2, null);

            if ($value === null || ! $this->matches(strtolower(rawurldecode($name)))) {
                return $pair;
            }

            return $name.'='.rawurlencode(self::MASK);
        }, explode('&', $query));

        return implode('&', $pairs).$fragment;
    }

    /**
     * Mask the token-shaped segments of the path and the password of the
     * userinfo. The authority (scheme, userinfo, host, port) ends at the
     * first slash after `//` or at a `#`, and the path at a `#`; neither the
     * authority nor the fragment is ever read as a segment, and the fragment
     * goes through scrubPairs().
     */
    private function scrubPath(string $base): string
    {
        if (preg_match('~^(https?://[^/#]*)([^#]*)(.*)$~is', $base, $parts) !== 1) {
            return $base;
        }

        [, $authority, $path, $fragment] = $parts;

        $segments = array_map(
            fn (string $segment): string => preg_match(self::PATH_TOKEN, $segment) === 1 ? rawurlencode(self::MASK) : $segment,
            explode('/', $path),
        );

        return $this->scrubUserinfo($authority).implode('/', $segments).$this->scrubPairs($fragment);
    }

    /**
     * A string that starts with an address of another scheme, a DSN above
     * all (`mysql://root:secret@db/app`, `redis://:secret@cache:6379`): the
     * password of its userinfo is masked, and so is the value of every query
     * pair whose name matches, since a DSN writes its options there
     * (`tcp://127.0.0.1:6379?password=...`). The path-token rule is the
     * web's alone: a DSN's path is a database name or a file. The address
     * ends at the first whitespace and the text after it is not read.
     */
    private function scrubOtherAddress(string $value): string
    {
        if (preg_match('~^(\s*+)([a-z][a-z0-9+.\-]*+://)(\S*+)~i', $value, $parts) !== 1) {
            return $value;
        }

        [$matched, $lead, $scheme, $address] = $parts;
        [$base, $query] = array_pad(explode('?', $address, 2), 2, null);
        $authority = strcspn($base, '/#');

        return $lead
            .$this->scrubUserinfo($scheme.substr($base, 0, $authority)).substr($base, $authority)
            .($query === null ? '' : '?'.$this->scrubQuery($query))
            .substr($value, strlen($matched));
    }

    /**
     * The authority with the password of its userinfo masked: everything
     * between the first `:` after `//` and the LAST `@`, since the host is
     * what follows the last one. The user stays, it says whose account the
     * address used, and so a credential written as the user
     * (`https://ghp_...@github.com`) stays with it; an authority with no `@`,
     * or a userinfo with no password, comes back as it came.
     */
    private function scrubUserinfo(string $authority): string
    {
        $start = strpos($authority, '://');
        $at = strrpos($authority, '@');

        if ($start === false || $at === false || $at < $start) {
            return $authority;
        }

        $start += 3;
        [$user, $password] = array_pad(explode(':', substr($authority, $start, $at - $start), 2), 2, null);

        return $password === null || $password === ''
            ? $authority
            : substr($authority, 0, $start).$user.':'.rawurlencode(self::MASK).substr($authority, $at);
    }

    /**
     * Mask the `name=value` pairs of a text that is not a query string of
     * its own: a fragment, or what follows the leading URL. A pair opens on
     * `&`, `?` or `#`, and its value runs to the next `&`, whitespace or the
     * end, so the sentence around it is handed back as it came.
     */
    private function scrubPairs(string $text): string
    {
        return preg_replace_callback(
            '/([&?#])([^&=\s?#]+)=([^&\s]*)/',
            fn (array $pair): string => $this->matches(strtolower(rawurldecode($pair[2])))
                ? $pair[1].$pair[2].'='.rawurlencode(self::MASK)
                : $pair[0],
            $text,
        ) ?? $text;
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
     * followed by a value: an assignment or key separator (`=`, `=>`, a single
     * `:`), an array index named in quotes and given one
     * (`$headers['Authorization'] = 'Bearer ...'`), a quoted name before a
     * comma (`define('API_KEY', ...)`), or a call whose first argument is a
     * literal (`setApiKey('sk_live...')`). A comparison counts as a value,
     * for a variable as for a quoted index (`$token === $expected`,
     * `$config['password'] == '...'`): its other side may be the secret
     * itself, written into the code. A line that only USES the name
     * (`Hash::check($password, ...)`, `csrf_token()`, WordPress's
     * `get_the_author()` against a list holding `auth`) carries no value and
     * stays: masking by bare substring made a WordPress snippet unreadable.
     * So does an index that is only read (`return $headers['Authorization'];`)
     * or that is a variable (`$data[$key] = ...`), and so does a static call:
     * `::` is a scope, not a separator, or `Auth::user()` and
     * `TokenMismatchException::expired()` would go, the line of the throw
     * included. A literal that names none of the words still travels; the
     * documentation says so. A needle with a hyphen or an underscore inside
     * it is tried in both spellings, `php_auth_pw` and `php-auth-pw` (see
     * $lineNeedles).
     *
     * @param  array<int, string>  $lines
     * @return array<int, string>
     */
    public function scrubLines(array $lines): array
    {
        return array_map(
            fn (string $line): string => $this->namesAValue($line) ? self::MASK : $line,
            $lines,
        );
    }

    private function namesAValue(string $line): bool
    {
        $lower = strtolower($line);

        foreach ($this->lineNeedles as $needle) {
            if ($needle === '' || ! str_contains($lower, $needle)) {
                continue;
            }

            // An assignment or key separator, a quoted index followed by `=`
            // (an assignment or a comparison), a quoted name before a comma,
            // or a call whose first argument is a literal; never a bare
            // comma, or `Hash::check($secretGuess, $hash)` would go too,
            // never an unquoted index, or `$data[$key] = ...` would, and
            // never the first colon of `::`, or every `Auth::` line would.
            if (preg_match('/'.preg_quote($needle, '/').'\w*(?:[\'"]?\s*(?:=>|=|:(?!:))|[\'"]\s*\]\s*=|[\'"]\s*,|\(\s*[\'"])/i', $line) === 1) {
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
        $name = self::name($key);

        foreach ($this->names as $needle) {
            if ($needle !== '' && str_contains($name, $needle)) {
                return true;
            }
        }

        $compact = str_replace(['-', '_'], '', $name);

        foreach ($this->compactNames as $needle) {
            if (str_contains($compact, $needle)) {
                return true;
            }
        }

        return false;
    }

    /**
     * A key or a query-string name as it is matched: lower-cased, with a
     * hyphen read as an underscore, since php-auth-pw and php_auth_pw name
     * the same value.
     */
    private static function name(string $name): string
    {
        return str_replace('-', '_', strtolower($name));
    }

    /**
     * A configured needle written without its separators, when it carries
     * one between two of its characters and neither starts nor ends with one:
     * `api_key` gives `apikey`, `x-forwarded-for` gives `xforwardedfor`,
     * while `token` (nothing to drop) and WordPress's `db_` (the separator
     * is part of the word) give nothing (see $compactNames).
     */
    private static function compactName(string $needle): ?string
    {
        if (preg_match('/^[^-_].*[-_].*[^-_]$/s', $needle) !== 1) {
            return null;
        }

        return str_replace(['-', '_'], '', $needle);
    }

    /**
     * A line needle with every hyphen or underscore that sits between two
     * letters or digits swapped for the other one, and nothing else touched:
     * `php_auth_pw` gives `php-auth-pw`, `db_` and `sk_` stay as they are
     * (see $lineNeedles).
     */
    private static function otherSpelling(string $needle): string
    {
        return (string) preg_replace_callback(
            '/(?<=[a-z0-9])[-_](?=[a-z0-9])/',
            fn (array $separator): string => $separator[0] === '-' ? '_' : '-',
            $needle,
        );
    }
}
