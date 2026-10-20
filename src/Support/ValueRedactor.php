<?php

namespace QuietGuard\Monitor\Support;

/**
 * Masks personal data and credentials by the shape of the VALUE, wherever
 * they sit.
 *
 * The Scrubber next to this one masks by key name, which is all it can do: it
 * never sees "jean@exemple.fr" written into the free text of an error message,
 * into a URL segment, or into a field somebody called "reference". That is the
 * larger share of what actually leaks, and the client is the only place it can
 * be caught, because once a payload is sent the value has already left.
 *
 * Precision is the whole point. A pattern that masks too much destroys the
 * ability to debug and gets switched off, which protects nobody, so the shapes
 * that carry a checksum are verified rather than merely matched: a sixteen digit
 * order reference is not a card number, and a string starting with two letters
 * is not an IBAN unless it passes mod 97. A credential is recognised by the
 * prefix its issuer stamps on it (`sk_live_`, `AKIA`, `ghp_`, `xoxb-`), which
 * is what makes the match exact: an ordinary word, a class name, a git hash or
 * a UUID carries none of them.
 *
 * Every replacement names what it hid. "User [redacted:email] not found" still
 * says what went wrong; "User [redacted] not found" says less for no extra
 * safety. The tag also tells a value match apart from a Scrubber key match.
 */
class ValueRedactor
{
    /**
     * The shapes that ARE a credential: a token an issuer stamped with its
     * prefix, a signed JWT, a private key block, a Laravel application key, a
     * Quiet Guard project key, and the password of a `user:password@host`
     * written into an address of any scheme.
     *
     * Grouped on purpose, and in this order. The server masks arriving reports
     * with this group alone (a client may have switched the personal shapes
     * off, knowingly), so the group has to be one list in one place. The key
     * block goes first because it may contain anything, the stamped tokens
     * before the URL password so that a token written as a password keeps its
     * own label, and the whole group before the personal shapes, whose digit
     * runs otherwise bite into a token (`ghp_0612345678...` came out as
     * `[redacted:phone]`).
     */
    public const CREDENTIALS = ['private_key', 'jwt', 'stripe', 'aws', 'aws_secret', 'github', 'gitlab', 'slack', 'app_key', 'project_key', 'url_password'];

    /**
     * The list every client shipped as its default before 0.6.0, and wrote
     * into the configuration it told its readers to publish. A copy of that
     * file names these five, in this order, and nothing else; read literally
     * it would switch every credential shape off for everyone who followed
     * the installation page, which is the "default in a template is a copy"
     * lesson once more. So this exact list is read as "the default", which
     * it was when it was written, and a client that wants exactly these five
     * writes them in another order or adds one.
     */
    public const LEGACY_DEFAULT = ['email', 'iban', 'nir', 'card', 'phone'];

    /**
     * The shapes that are personal data, in the order they are applied.
     *
     * Order matters where shapes overlap: an IBAN before a card so its digits
     * are not read as one, a French social security number before a card so the
     * fifteen digits that occasionally satisfy Luhn are labelled for what they
     * are, and a card before a phone so a sixteen digit run is not partly eaten
     * by a ten digit pattern.
     */
    public const PERSONAL = ['email', 'iban', 'nir', 'card', 'phone'];

    /**
     * Built-in patterns, in the order they are applied: the credentials, then
     * the personal shapes.
     */
    public const PATTERNS = [...self::CREDENTIALS, ...self::PERSONAL];

    /**
     * What replaces a whole field the engine could not read: a PCRE failure on
     * a built-in pattern, or on a custom one that compiled. The field is
     * withheld rather than sent as it came, because "could not scan" and
     * "nothing to mask" are not the same verdict, and the value that defeats
     * the scanner is exactly the one nobody has looked at.
     */
    public const UNSCANNABLE = '[redacted:unscannable]';

    /**
     * A string longer than this is read in pieces (see chunks()), never
     * skipped. It used to be left alone whole, on the reasoning that a payload
     * that big is a dump rather than a message; a dump is also where a
     * connection string or a key block ends up, so the size is now a reason to
     * cut the work, not to skip it.
     */
    public const CHUNK_BYTES = 65536;

    /**
     * A mask as mask() writes it, the custom labels included.
     */
    private const MASK_PATTERN = '~(\[redacted:[^\]\s\[]*\])~';

    /** @var array<int, string> */
    private array $enabled;

    /**
     * The custom patterns that compile. One that does not is a configuration
     * error and is dropped here, once, rather than failing the field at every
     * report: the field is readable, the pattern is not.
     *
     * @var array<string, string>
     */
    private array $custom = [];

    /**
     * @param  array<int, string>  $enabled  built-in pattern names to apply
     * @param  array<string, string>  $custom  label => PCRE pattern, applied last
     */
    public function __construct(array $enabled = self::PATTERNS, array $custom = [])
    {
        if (array_values($enabled) === self::LEGACY_DEFAULT) {
            $enabled = self::PATTERNS;
        }

        $this->enabled = array_values(array_intersect(self::PATTERNS, $enabled));

        foreach ($custom as $label => $pattern) {
            if (is_string($pattern) && @preg_match($pattern, '') !== false) {
                $this->custom[(string) $label] = $pattern;
            }
        }
    }

    /**
     * Mask every recognised value in a string.
     *
     * Never throws: a redaction failure must not be the reason an application
     * stops reporting its errors. It never hands back a value it could not
     * read either: when the engine fails on a pattern that compiled, the whole
     * field is replaced by UNSCANNABLE (see redactChunk()).
     */
    public function redact(string $text): string
    {
        if ($text === '') {
            return $text;
        }

        if (strlen($text) <= self::CHUNK_BYTES) {
            return $this->redactChunk($text, $this->enabled);
        }

        // The key block is the one shape that spans lines, so it is the one
        // shape a chunk boundary could cut in two: it is read on the whole
        // text first, and the chunks are read without it.
        $names = $this->enabled;

        if (in_array('private_key', $names, true)) {
            $text = $this->apply($text, 'private_key');

            if ($text === null) {
                return self::UNSCANNABLE;
            }

            $names = array_values(array_diff($names, ['private_key']));
        }

        $out = '';

        foreach ($this->chunks($text) as $chunk) {
            $redacted = $this->redactChunk($chunk, $names);

            if ($redacted === self::UNSCANNABLE) {
                return self::UNSCANNABLE;
            }

            $out .= $redacted;
        }

        return $out;
    }

    /**
     * Mask recognised values throughout a structure, keys included.
     *
     * Keys are redacted too: an array keyed by email address would otherwise
     * publish every address in its keys while its values were being cleaned.
     *
     * @param  array<mixed>  $data
     * @return array<mixed>
     */
    public function redactAll(array $data): array
    {
        $out = [];

        foreach ($data as $key => $value) {
            if (is_string($key)) {
                $masked = $this->redact($key);

                // Two keys masked to the same label would land on one slot
                // and the second would silently replace the first; each
                // keeps a row of its own.
                for ($n = 2, $key = $masked; array_key_exists($key, $out); $n++) {
                    $key = $masked.' ('.$n.')';
                }
            }

            $out[$key] = match (true) {
                is_string($value) => $this->redact($value),
                is_array($value) => $this->redactAll($value),
                default => $value,
            };
        }

        return $out;
    }

    public function mask(string $label): string
    {
        return '[redacted:'.$label.']';
    }

    /**
     * One piece of text through every enabled pattern, then the custom ones,
     * as it is written and then decoded where it is percent-encoded
     * (redactEncodedRuns()).
     *
     * @param  array<int, string>  $names
     */
    private function redactChunk(string $text, array $names): string
    {
        $text = $this->redactPlain($text, $names);

        if ($text === self::UNSCANNABLE || ! str_contains($text, '%')) {
            return $text;
        }

        return $this->redactEncodedRuns($text);
    }

    /**
     * The shapes in the percent-encoded runs of a text, read decoded.
     *
     * An address is written encoded: `fullUrl()` in Laravel and `getUri()` in
     * Symfony both rewrite the query string in RFC 3986 form, so the email a
     * visitor typed into `?email=` travels as `jeanne.martin%40example.fr`, a
     * number written with spaces as `06%2012%2034%2056%2078`, a DSN passed as
     * a parameter as `redis%3A%2F%2Fu%3Asecret%40cache`. Read as typed, none
     * of those is the shape its pattern knows, and they went out in clear in
     * the `url` field while the same values were masked in the `query` array
     * beside it.
     *
     * A run is a stretch of the characters an encoded value is written with
     * (the unreserved ones, `:`, `@` and the sub-delimiters but `&` and `=`)
     * holding at least one `%XX`; `/`, `?`, `#`, `&`, `=`, `[`, `]` and
     * whitespace end it, so a name is
     * never decoded into its value and a path segment never into the next.
     * Each run is decoded once (rawurldecode: a `+` stays a `+`, so a
     * `q=jeanne+martin` is not touched), read by the same patterns, and when
     * nothing changes it is handed back byte for byte. When something does,
     * only the part that changed is rewritten: the bytes before and after it
     * keep their original spelling, the mask is written as the redactor
     * writes it anywhere else, `[redacted:email]`, unencoded so the address
     * stays readable and the same mask is found whether the value came
     * encoded or not, and what sits between two masks of one run is
     * re-encoded with rawurlencode, the form both frameworks use. A mask
     * holds no run character (`[` ends a run), so a second pass reads
     * nothing new: the rule is idempotent.
     *
     * Every enabled pattern applies to a decoded run, the key block included
     * (a long text read in chunks has had it removed from the chunk list,
     * since it is read on the whole text first; encoded, it sits inside one
     * run). A single decoding: a value encoded twice (`%2540`) is not
     * opened.
     */
    private function redactEncodedRuns(string $text): string
    {
        $failed = false;

        $out = @preg_replace_callback(
            '~(?:[A-Za-z0-9._\~!$\'()*+,;:@\-]++|%[0-9A-Fa-f]{2})++~',
            function (array $m) use (&$failed): string {
                $run = $m[0];

                if ($failed || ! str_contains($run, '%')) {
                    return $run;
                }

                $rewritten = $this->redactRun($run);

                if ($rewritten === null) {
                    $failed = true;

                    return $run;
                }

                return $rewritten;
            },
            $text,
        );

        return ! is_string($out) || $failed ? self::UNSCANNABLE : $out;
    }

    /**
     * One encoded run, its shapes masked; null when the engine failed.
     *
     * Each decoded byte remembers where it came from, so the part that
     * changed is located in the decoded text (the longest common prefix and
     * suffix of before and after) and replaced in the original run, the rest
     * of which stays as it was written.
     */
    private function redactRun(string $run): ?string
    {
        $decoded = '';
        $origin = [];
        $length = strlen($run);

        for ($i = 0; $i < $length;) {
            $origin[] = $i;

            // The run pattern admits a `%` only before two hex digits.
            if ($run[$i] === '%') {
                $decoded .= chr((int) hexdec(substr($run, $i + 1, 2)));
                $i += 3;
            } else {
                $decoded .= $run[$i];
                $i++;
            }
        }

        $origin[] = $length;
        $redacted = $this->redactPlain($decoded, $this->enabled);

        if ($redacted === self::UNSCANNABLE) {
            return null;
        }

        if ($redacted === $decoded) {
            return $run;
        }

        $before = strlen($decoded);
        $after = strlen($redacted);
        $prefix = 0;

        while ($prefix < $before && $prefix < $after && $decoded[$prefix] === $redacted[$prefix]) {
            $prefix++;
        }

        $suffix = 0;

        while ($suffix < $before - $prefix && $suffix < $after - $prefix && $decoded[$before - 1 - $suffix] === $redacted[$after - 1 - $suffix]) {
            $suffix++;
        }

        // A mask is written whole or not at all: a common prefix or suffix
        // that stops inside one would encode half of it.
        preg_match_all(self::MASK_PATTERN, $redacted, $masks, PREG_OFFSET_CAPTURE);

        foreach ($masks[0] as [$mask, $start]) {
            $end = $start + strlen($mask);

            if ($start < $prefix && $prefix < $end) {
                $prefix = $start;
            }

            if ($start < $after - $suffix && $after - $suffix < $end) {
                $suffix = $after - $end;
            }
        }

        $middle = substr($redacted, $prefix, $after - $prefix - $suffix);
        $pieces = preg_split(self::MASK_PATTERN, $middle, -1, PREG_SPLIT_DELIM_CAPTURE) ?: [$middle];
        $written = '';

        foreach ($pieces as $index => $piece) {
            $written .= $index % 2 === 1 ? $piece : rawurlencode($piece);
        }

        return substr($run, 0, $origin[$prefix]).$written.substr($run, $origin[$before - $suffix]);
    }

    /**
     * One piece of text through every enabled pattern, then the custom ones,
     * as it is written.
     *
     * @param  array<int, string>  $names
     */
    private function redactPlain(string $text, array $names): string
    {
        foreach ($names as $name) {
            $text = $this->apply($text, $name);

            if ($text === null) {
                return self::UNSCANNABLE;
            }
        }

        foreach ($this->custom as $label => $pattern) {
            $replaced = @preg_replace($pattern, $this->mask($label), $text);

            // The pattern compiled (the constructor checked), so a null here
            // is the engine giving up on this value: a backtrack or recursion
            // limit, or bytes that are not the UTF-8 the pattern asked for.
            if (! is_string($replaced)) {
                return self::UNSCANNABLE;
            }

            $text = $replaced;
        }

        return $text;
    }

    /**
     * A long text in pieces no pattern straddles.
     *
     * Every shape but the key block sits on one line, so a piece ends on the
     * last line break of the window; a window with no line break ends on its
     * last space, and one with no space on its last byte outside the alphabet
     * every token is written in, the backslash of an escaped slash (`\/`, as
     * json_encode writes it) included. A window with none of those is one run of
     * token characters, a blob, and is cut where it is: the half of a token
     * on either side of that cut is not a token any more.
     *
     * @return iterable<int, string>
     */
    private function chunks(string $text): iterable
    {
        $length = strlen($text);
        $offset = 0;

        while ($offset < $length) {
            $size = min(self::CHUNK_BYTES, $length - $offset);

            if ($offset + $size < $length) {
                $window = substr($text, $offset, $size);
                $cut = strrpos($window, "\n");

                if ($cut === false) {
                    $cut = strrpos($window, ' ');
                }

                if ($cut === false && preg_match('~[^A-Za-z0-9_+/=.:@%\\\-](?=[A-Za-z0-9_+/=.:@%\\\-]*+$)~D', $window, $m, PREG_OFFSET_CAPTURE) === 1) {
                    $cut = $m[0][1];
                }

                if ($cut !== false && $cut > 0) {
                    $size = $cut + 1;
                }

                // Never between the bytes of one character: a piece that
                // ends inside a multi-byte sequence is not UTF-8 any more,
                // and a custom pattern written with `/u` then fails on it.
                // The byte after the cut must not be a continuation byte.
                while ($size > 1 && $offset + $size < $length && (ord($text[$offset + $size]) & 0xC0) === 0x80) {
                    $size--;
                }
            }

            yield substr($text, $offset, $size);

            $offset += $size;
        }
    }

    /**
     * One pattern over the text. Null when the engine failed, which the
     * caller turns into UNSCANNABLE; the old behaviour, handing the text back
     * as it came, sent precisely the value nothing had read.
     */
    private function apply(string $text, string $name): ?string
    {
        $replaced = @preg_replace_callback(
            $this->pattern($name),
            fn (array $m): string => $this->replacement($name, $m),
            $text,
        );

        return is_string($replaced) ? $replaced : null;
    }

    private function pattern(string $name): string
    {
        return match ($name) {
            // From the BEGIN line to the END line, PGP's "PRIVATE KEY BLOCK"
            // included; a block whose END is missing (the message was cut
            // before it) is masked to the end of the text, since the key is
            // what was cut, not the marker. Possessive runs rather than a
            // lazy `[\s\S]*?`: the lazy form counted one backtrack per byte
            // and gave up on a block of a megabyte, which then came out as
            // unscannable where it should have come out masked.
            'private_key' => '~-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----(?:[^-]++|-(?!----END ))*+(?:-----END (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----)?~',

            // Three base64url parts, the first two opening on `{"` (`eyJ`);
            // the signature may be empty (alg: none). Confirmed by decoding
            // the header.
            'jwt' => '~(?<![A-Za-z0-9_\-])eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*~',

            // Secret and restricted keys, live or test, and webhook signing
            // secrets. Publishable keys (pk_) are meant to be public.
            'stripe' => '~(?<![A-Za-z0-9_])(?:(?:sk|rk)_(?:live|test)|whsec)_[A-Za-z0-9]{8,}~',

            // An access key id: AKIA (long-term) or ASIA (temporary), then
            // sixteen upper-case letters or digits, exactly.
            'aws' => '~(?<![A-Za-z0-9/+])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Za-z0-9])~',

            // The secret access key is forty base64 characters with no
            // prefix at all: alone, that is the shape of any hash or token,
            // and masking every one of them is the pattern somebody switches
            // off. It is masked only where it is known for what it is: within
            // eighty characters after an access key id (just masked by the
            // pattern above, hence the label it looks for), or after the
            // name `aws_secret_access_key` / `aws_secret_key`. The anchor is
            // kept, the forty characters go.
            'aws_secret' => '~((?:\[redacted:aws\]|aws_secret(?:_access)?_key)[^\n]{0,80}?)(?<![A-Za-z0-9/+])([A-Za-z0-9/+]{40})(?![A-Za-z0-9/+=])~i',

            // Classic and fine-grained personal access tokens, OAuth, user,
            // server and refresh tokens.
            'github' => '~(?<![A-Za-z0-9_])(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})~',

            // Personal, runner, deploy, pipeline trigger, feature flag,
            // incoming mail, agent and CI job tokens, and OAuth application
            // secrets: every prefix GitLab documents for a token it issues.
            'gitlab' => '~(?<![A-Za-z0-9_])gl(?:pat|rt|dt|oas|ptt|ffct|imt|agent|cbt|soat)-[A-Za-z0-9_\-]{20,}~',

            // Bot, user, app-level, refresh and legacy tokens, and the
            // address of an incoming webhook, whose path IS the secret: the
            // host and `/services/` stay, the three segments go.
            'slack' => '~(https:(?:\\\\?/){2}hooks\.slack\.com(?:\\\\?/)services(?:\\\\?/))[A-Za-z0-9]+(?:\\\\?/)[A-Za-z0-9]+(?:\\\\?/)[A-Za-z0-9]+|(?<![A-Za-z0-9_])(?:xox[abeprs]|xapp)-[A-Za-z0-9\-]{10,}~',

            // The form `php artisan key:generate` writes: `base64:` then
            // thirty-two bytes, forty-four characters ending on one `=`. An
            // `=` may precede it: that is how a .env line writes it. A slash
            // may arrive escaped (`\/`): that is how json_encode() writes it,
            // and a Livewire snapshot or a dumped array is a JSON string.
            'app_key' => '~(?<![A-Za-z0-9+/])base64:(?:[A-Za-z0-9+]|\\\\?/){43}=(?![A-Za-z0-9+/=])~',

            // Our own: `lm_` and the forty characters ProjectToken::generate
            // draws (see the server's App\Models\ProjectToken).
            'project_key' => '~(?<![A-Za-z0-9_])lm_[A-Za-z0-9]{40}(?![A-Za-z0-9])~',

            // `scheme://user:password@`, anywhere in the text and for any
            // scheme (a DSN above all): the password goes, the scheme, the
            // user and what follows the `@` stay, so the sentence still says
            // which host and whose account.
            //
            // Four shapes a first version missed, each measured: the slashes
            // of the separator may be escaped (`redis:\/\/`, json_encode);
            // the user may carry an `@` (a mailer DSN's `postmaster@domain`),
            // so it is read up to the first `:`; the password may carry an
            // `@` (`p@ssw0rd`), so it runs to the LAST `@` the authority
            // holds; and it may carry a `/` (a base64 one), which is admitted
            // only when what precedes the first `/` is not a bare port
            // number, or `https://host:8080/users/a@b.fr` would read the
            // port as a user. Every candidate `@` has to be followed by a
            // host and then a delimiter, which is what tells the last `@` of
            // the authority from one in a path or a query. The user may
            // already be a mask (a token written there was labelled a step
            // earlier), whose own colon must not be read as the separator.
            'url_password' => '~(?<![A-Za-z0-9+.\-])([a-z][a-z0-9+.\-]*:(?:\\\\?/){2}(?:\[redacted:[a-z_]+\]|[^\s/:"\'\\\\]*):)((?:(?!\d+/)[^\s"\'?\\\\]+|[^\s"\'?/\\\\]+))@(?=[A-Za-z0-9._\-\[\]]+(?::\d+)?(?:[\s/?#"\']|\\\\/|$))~i',

            // Deliberately not RFC 5322. That grammar matches things nobody
            // types and is a backtracking hazard in a hot path.
            'email' => '/[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}/',

            // Two letters, two check digits, then the national part. The
            // lookarounds keep it from biting into a longer token.
            'iban' => '/(?<![A-Za-z0-9])[A-Z]{2}[0-9]{2}(?:[ ]?[A-Z0-9]{4}){2,7}(?:[ ]?[A-Z0-9]{1,3})?(?![A-Za-z0-9])/',

            // Thirteen to nineteen digits, spaces or dashes allowed between
            // them. Confirmed by Luhn, without which every long id would match.
            'card' => '/(?<!\d)(?:\d[ \-]?){12,18}\d(?!\d)/',

            // French social security number: sex, year, month, department and
            // order, with its two check digits.
            'nir' => '/(?<!\d)[12][0-9]{2}(?:0[1-9]|1[0-2]|[2-9][0-9])(?:[0-9]{2}|2[AB])[0-9]{3}[0-9]{3}[0-9]{2}(?!\d)/i',

            // French numbering plan only: +33 or a leading zero, then a nine
            // digit subscriber number. A bare ten digit run is NOT matched,
            // because an order reference looks exactly like one.
            'phone' => '/(?<![\d+])(?:\+33[ .\-]?|0)[1-9](?:[ .\-]?\d{2}){4}(?!\d)/',

            default => '/(?!)/',
        };
    }

    /**
     * What a match becomes: its mask, or itself when the second opinion says
     * it is not what it looked like.
     *
     * @param  array<int|string, string>  $m
     */
    private function replacement(string $name, array $m): string
    {
        if ($name === 'url_password') {
            // A password that is already a mask stays one: a token written
            // there was labelled by its own pattern a step earlier.
            return str_starts_with($m[2], '[redacted:')
                ? $m[0]
                : $m[1].$this->mask('password').'@';
        }

        // The shapes that keep an anchor and mask what follows it: the
        // webhook host before a Slack path, the key id or the name before
        // an AWS secret.
        if (in_array($name, ['slack', 'aws_secret'], true) && isset($m[1]) && $m[1] !== '') {
            return $m[1].$this->mask($name);
        }

        return $this->confirms($name, $m[0]) ? $this->mask($name) : $m[0];
    }

    /**
     * Second opinion for the shapes that carry a checksum, or a structure.
     */
    private function confirms(string $name, string $match): bool
    {
        return match ($name) {
            'card' => $this->passesLuhn(preg_replace('/\D/', '', $match) ?? ''),
            'iban' => $this->passesMod97(preg_replace('/\s/', '', $match) ?? ''),
            'nir' => $this->passesNirKey(self::corsicaToDigits($match)),
            'jwt' => $this->decodesToJsonObject(strtok($match, '.')),
            default => true,
        };
    }

    /**
     * Whether a base64url part decodes to a JSON object, which the header of
     * a JWT must. Decoded and parsed, not merely opened on `{`: every `eyJ`
     * decodes to `{"`, so the opening brace alone confirms nothing.
     */
    private function decodesToJsonObject(string|false $part): bool
    {
        if ($part === false) {
            return false;
        }

        $json = base64_decode(strtr($part, '-_', '+/'), true);

        return is_string($json) && is_array(json_decode($json, true));
    }

    private function passesLuhn(string $digits): bool
    {
        $length = strlen($digits);

        if ($length < 13 || $length > 19) {
            return false;
        }

        $sum = 0;

        foreach (array_reverse(str_split($digits)) as $index => $digit) {
            $digit = (int) $digit;

            if ($index % 2 === 1) {
                $digit *= 2;

                if ($digit > 9) {
                    $digit -= 9;
                }
            }

            $sum += $digit;
        }

        return $sum % 10 === 0;
    }

    private function passesMod97(string $iban): bool
    {
        if (strlen($iban) < 15 || strlen($iban) > 34) {
            return false;
        }

        // Move the country code and check digits to the end, then read every
        // letter as its position in the alphabet plus nine.
        $rearranged = substr($iban, 4).substr($iban, 0, 4);
        $numeric = '';

        foreach (str_split(strtoupper($rearranged)) as $char) {
            if (ctype_digit($char)) {
                $numeric .= $char;

                continue;
            }

            if (! ctype_alpha($char)) {
                return false;
            }

            $numeric .= (string) (ord($char) - 55);
        }

        // bcmod would be cleaner but the extension is not guaranteed on a
        // client's server, so the remainder is carried through in chunks.
        $remainder = 0;

        foreach (str_split($numeric, 7) as $chunk) {
            $remainder = (int) ((string) $remainder.$chunk) % 97;
        }

        return $remainder === 1;
    }

    /**
     * La Corse en chiffres, sans quoi son NIR n'est jamais masqué.
     *
     * Le motif accepte 2A et 2B comme département, et la clé de contrôle est
     * calculée sur les chiffres seuls : retirer les non-chiffres laissait 14
     * caractères là où la vérification en exige 15, donc elle répondait TOUJOURS
     * faux et un NIR corse traversait en clair. Le motif annonçait la Corse et
     * la clé la rendait inatteignable.
     *
     * 2A vaut 19 et 2B vaut 18 : c'est la règle officielle du calcul, pas une
     * approximation, et elle s'applique avant le modulo 97.
     */
    private static function corsicaToDigits(string $match): string
    {
        $normalised = str_ireplace(['2A', '2B'], ['19', '18'], $match);

        return preg_replace('/\D/', '', $normalised) ?? '';
    }

    private function passesNirKey(string $digits): bool
    {
        if (strlen($digits) !== 15) {
            return false;
        }

        $body = substr($digits, 0, 13);
        $key = (int) substr($digits, 13, 2);

        return 97 - ((int) $body % 97) === $key;
    }
}
