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
    public const CREDENTIALS = ['private_key', 'jwt', 'stripe', 'aws', 'aws_secret', 'github', 'gitlab', 'slack', 'app_key', 'project_key', 'aws_presigned', 'url_password'];

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
    private const MASK_PATTERN = '~(\[redacted:[^\]\[\n]*\])~';

    /**
     * How many times an encoded text is decoded: once for the address
     * `fullUrl()` writes, and twice more for an address passed as one of its
     * parameters, encoded again (`%2540` is an `@` encoded twice).
     */
    private const MAX_DECODINGS = 3;

    /**
     * What a `&` decoded from `%26` is written as in a decoded layer: a
     * byte no pattern treats as a separator. Encoded, the `&` belongs to
     * the value (a password, a query passed as a parameter); written, it
     * separates two parameters, and url_password only ends an address on
     * that one. Never written out: what leaves a decoded layer is the
     * original spelling, or a mask.
     */
    private const ENCODED_AMPERSAND = "\x00";

    /**
     * A decoded layer is opened only when one of its escapes decodes to
     * something other than a letter or a digit: an escape of `A` or `7`
     * hides no separator, and frameworks never write one.
     */
    private const OPENING_ESCAPE = '/%(?![46][1-9A-Fa-f]|[57][0-9Aa]|3[0-9])[0-9A-Fa-f]{2}/';

    /**
     * The longest string redactAll() remembers the answer for: a context
     * often repeats the same short value, and one that is long is not
     * worth holding twice.
     */
    private const MEMO_BYTES = 1024;

    /** @var array<int, string> */
    private array $enabled;

    /**
     * The enabled credential shapes, in the order they are applied.
     *
     * @var array<int, string>
     */
    private array $credentials;

    /**
     * The enabled personal shapes, in the order they are applied.
     *
     * @var array<int, string>
     */
    private array $personal;

    /**
     * The custom patterns that compile. One that does not is a configuration
     * error and is dropped here, once, rather than failing the field at every
     * report: the field is readable, the pattern is not. So is one whose
     * label holds a bracket or a line break: its mask would not read as one.
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
        $this->credentials = array_values(array_intersect($this->enabled, self::CREDENTIALS));
        $this->personal = array_values(array_intersect($this->enabled, self::PERSONAL));

        foreach ($custom as $label => $pattern) {
            if (is_string($pattern) && preg_match('/[\[\]\n]/', (string) $label) !== 1 && @preg_match($pattern, '') !== false) {
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
            return $this->redactChunk($text, $this->credentials);
        }

        // The key block is the one shape that spans lines, so it is the one
        // shape a chunk boundary could cut in two: it is read on the whole
        // text first, and the chunks are read without it.
        $credentials = $this->credentials;

        if (in_array('private_key', $credentials, true)) {
            $applied = $this->apply($text, 'private_key', 0, null);

            if ($applied === null) {
                return self::UNSCANNABLE;
            }

            $text = $applied[0];
            $credentials = array_values(array_diff($credentials, ['private_key']));
        }

        $out = '';

        foreach ($this->chunks($text) as $chunk) {
            $redacted = $this->redactChunk($chunk, $credentials);

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
     * A short string met twice is read once.
     *
     * @param  array<mixed>  $data
     * @return array<mixed>
     */
    public function redactAll(array $data): array
    {
        $memo = [];

        return $this->redactStructure($data, $memo);
    }

    public function mask(string $label): string
    {
        return '[redacted:'.$label.']';
    }

    /**
     * @param  array<mixed>  $data
     * @param  array<string, string>  $memo
     * @return array<mixed>
     */
    private function redactStructure(array $data, array &$memo): array
    {
        $out = [];

        foreach ($data as $key => $value) {
            if (is_string($key)) {
                $masked = $this->remembered($key, $memo);

                // Two keys masked to the same label would land on one slot
                // and the second would silently replace the first; each
                // keeps a row of its own.
                for ($n = 2, $key = $masked; array_key_exists($key, $out); $n++) {
                    $key = $masked.' ('.$n.')';
                }
            }

            $out[$key] = match (true) {
                is_string($value) => $this->remembered($value, $memo),
                is_array($value) => $this->redactStructure($value, $memo),
                default => $value,
            };
        }

        return $out;
    }

    /**
     * @param  array<string, string>  $memo
     */
    private function remembered(string $text, array &$memo): string
    {
        if (strlen($text) > self::MEMO_BYTES) {
            return $this->redact($text);
        }

        return $memo[$text] ??= $this->redact($text);
    }

    /**
     * One piece of text through every enabled pattern, then the custom ones,
     * in three passes: the credentials as the text is written, then the text
     * decoded where it is percent-encoded (redactDecoded()), then the
     * personal shapes and the custom patterns as it is written.
     *
     * The credentials go first, as written, so that an address whose
     * password carries an escape (`redis://u:p%40ss@cache.internal`) has its
     * password masked before decoding reads `ss@cache.internal` as an email.
     * The decoded pass goes before the personal shapes, because those would
     * otherwise cut into a credential the written form hides: a GitHub token
     * after `%3D` (`?next=https%3A%2F%2Fapi.test%2Fcb%3Ftoken%3Dghp_Ab0612...`)
     * fails its own lookbehind as written, and `phone` then bit `0612345678`
     * out of it.
     *
     * @param  array<int, string>  $credentials
     */
    private function redactChunk(string $text, array $credentials): string
    {
        return $this->redactLayer($text, $credentials, 0, null)[0] ?? self::UNSCANNABLE;
    }

    /**
     * The three passes of redactChunk() at one level of decoding; null when
     * the engine failed.
     *
     * Below the first level every change is recorded: the result comes back
     * with, for each of its bytes, the position in `$text` it came from, or
     * -1 for a byte a mask put there (null when nothing changed). That is
     * what lets redactDecoded() write back only the values, in the encoded
     * text, every other byte as it was written.
     *
     * @param  array<int, string>  $credentials
     * @return array{0: string, 1: array<int, int>|null}|null
     */
    private function redactLayer(string $text, array $credentials, int $depth, ?string $parent): ?array
    {
        $track = $depth > 0;
        $map = null;

        foreach ($credentials as $name) {
            $step = $this->apply($text, $name, $depth, $parent);

            if ($step === null) {
                return null;
            }

            [$text, $map] = $this->advance($text, $map, $step, $track);
        }

        $opens = $depth < self::MAX_DECODINGS ? preg_match(self::OPENING_ESCAPE, $text) : 0;

        if ($opens === false) {
            return null;
        }

        if ($opens === 1) {
            $step = $this->redactDecoded($text, $depth);

            if ($step === null) {
                return null;
            }

            [$text, $map] = $this->advance($text, $map, $step, $track);
        }

        foreach ($this->personal as $name) {
            $step = $this->apply($text, $name, $depth, $parent);

            if ($step === null) {
                return null;
            }

            [$text, $map] = $this->advance($text, $map, $step, $track);
        }

        foreach ($this->custom as $label => $pattern) {
            $step = $this->applyCustom($text, $label, $pattern, $depth);

            if ($step === null) {
                return null;
            }

            [$text, $map] = $this->advance($text, $map, $step, $track);
        }

        // The AWS secret is found within eighty characters after its key
        // id, a distance the masks put since have shortened: read again on
        // the final text, or a second pass found what the first had missed.
        if (in_array('aws_secret', $credentials, true)) {
            $step = $this->apply($text, 'aws_secret', $depth, $parent);

            if ($step === null) {
                return null;
            }

            [$text, $map] = $this->advance($text, $map, $step, $track);
        }

        return [$text, $map];
    }

    /**
     * The text after one pass, and the origin of each of its bytes when it
     * is tracked.
     *
     * @param  array<int, int>|null  $map
     * @param  array{0: string, 1: array<int, array{0: int, 1: int, 2: string}>}  $step
     * @return array{0: string, 1: array<int, int>|null}
     */
    private function advance(string $text, ?array $map, array $step, bool $track): array
    {
        [$next, $edits] = $step;

        if (! $track || $edits === []) {
            return [$next, $map];
        }

        $map ??= $text === '' ? [] : range(0, strlen($text) - 1);
        $out = [];
        $cursor = 0;

        foreach ($edits as [$start, $end, $replacement]) {
            for ($i = $cursor; $i < $start; $i++) {
                $out[] = $map[$i];
            }

            for ($i = 0, $length = strlen($replacement); $i < $length; $i++) {
                $out[] = -1;
            }

            $cursor = $end;
        }

        for ($i = $cursor, $length = count($map); $i < $length; $i++) {
            $out[] = $map[$i];
        }

        return [$next, $out];
    }

    /**
     * The shapes of a text read decoded where it is percent-encoded, and
     * where in the text what changed sits.
     *
     * An address is written encoded: `fullUrl()` in Laravel and `getUri()` in
     * Symfony both rewrite the query string in RFC 3986 form, so the email a
     * visitor typed into `?email=` travels as `jeanne.martin%40example.fr`, a
     * number written with spaces as `06%2012%2034%2056%2078`, a DSN passed as
     * a parameter as `redis%3A%2F%2Fu%3Asecret%40cache`. Read as written,
     * none of those is the shape its pattern knows, and they went out in
     * clear in the `url` field while the same values were masked in the
     * `query` array beside it.
     *
     * Every `%XX` of the text is decoded at once (a `+` stays a `+`: a form
     * body quoted with `+` for its spaces is not read as spaced; a `%26` is
     * written ENCODED_AMPERSAND), and each decoded byte remembers where it
     * was written. The decoded text goes through redactLayer() one level
     * down, every enabled pattern included (the key block too, which a long
     * text read in chunks has had removed from its list), so an address
     * passed as a parameter and encoded again
     * (`next=...%3Femail%3Djeanne%2540example.fr`) is opened in turn, up to
     * MAX_DECODINGS levels.
     *
     * Every pass below records where it put a mask, so only the values are
     * written back: every other byte keeps the spelling it was written
     * with, and the mask is written unencoded, `[redacted:email]`, as the
     * redactor writes it anywhere else.
     *
     * @return array{0: string, 1: array<int, array{0: int, 1: int, 2: string}>}|null
     */
    private function redactDecoded(string $text, int $depth): ?array
    {
        $parts = preg_split('/(%[0-9A-Fa-f]{2})/', $text, -1, PREG_SPLIT_DELIM_CAPTURE);

        if (! is_array($parts)) {
            return null;
        }

        $decoded = '';
        $origin = [];
        $offset = 0;

        foreach ($parts as $index => $part) {
            if ($index % 2 === 1) {
                $origin[] = $offset;
                $byte = chr((int) hexdec(substr($part, 1)));
                $decoded .= $byte === '&' ? self::ENCODED_AMPERSAND : $byte;
                $offset += 3;

                continue;
            }

            for ($i = 0, $length = strlen($part); $i < $length; $i++) {
                $origin[] = $offset + $i;
            }

            $decoded .= $part;
            $offset += strlen($part);
        }

        $origin[] = $offset;
        $layer = $this->redactLayer($decoded, $this->credentials, $depth + 1, $text);

        if ($layer === null) {
            return null;
        }

        [$out, $map] = $layer;

        if ($map === null) {
            return [$text, []];
        }

        // Back to the written text: a run of decoded bytes in order is
        // written as it was, anything a mask put in place of a run is an
        // edit of the text.
        $edits = [];
        $expected = 0;
        $inserted = '';

        for ($i = 0, $length = strlen($out); $i < $length; $i++) {
            $from = $map[$i];

            if ($from === -1) {
                $inserted .= $out[$i];

                continue;
            }

            if ($from !== $expected || $inserted !== '') {
                $edits[] = [$origin[$expected], $origin[$from], str_replace(self::ENCODED_AMPERSAND, '%26', $inserted)];
                $inserted = '';
            }

            $expected = $from + 1;
        }

        if ($expected !== strlen($decoded) || $inserted !== '') {
            $edits[] = [$origin[$expected], $origin[strlen($decoded)], str_replace(self::ENCODED_AMPERSAND, '%26', $inserted)];
        }

        return [self::rewrite($text, $edits), $edits];
    }

    /**
     * A text with its edits applied, each [start, end, replacement] in the
     * text's own positions, in order.
     *
     * @param  array<int, array{0: int, 1: int, 2: string}>  $edits
     */
    private static function rewrite(string $text, array $edits): string
    {
        $out = '';
        $cursor = 0;

        foreach ($edits as [$start, $end, $replacement]) {
            $out .= substr($text, $cursor, $start - $cursor).$replacement;
            $cursor = $end;
        }

        return $out.substr($text, $cursor);
    }

    /**
     * Record that `$match`, found at `$at`, became `$replacement`: only the
     * part between their common start and their common end, widened so that
     * a mask is never split between what was kept and what was written.
     *
     * @param  array<int, array{0: int, 1: int, 2: string}>  $edits
     */
    private static function edit(array &$edits, int $at, string $match, string $replacement): void
    {
        if ($match === $replacement) {
            return;
        }

        $matched = strlen($match);
        $written = strlen($replacement);
        $prefix = 0;

        while ($prefix < $matched && $prefix < $written && $match[$prefix] === $replacement[$prefix]) {
            $prefix++;
        }

        $suffix = 0;

        while ($suffix < $matched - $prefix && $suffix < $written - $prefix && $match[$matched - 1 - $suffix] === $replacement[$written - 1 - $suffix]) {
            $suffix++;
        }

        preg_match_all(self::MASK_PATTERN, $replacement, $masks, PREG_OFFSET_CAPTURE);

        foreach ($masks[0] as [$mask, $start]) {
            $end = $start + strlen($mask);

            if ($start < $prefix && $prefix < $end) {
                $prefix = $start;
            }

            if ($start < $written - $suffix && $written - $suffix < $end) {
                $suffix = $written - $end;
            }
        }

        $edits[] = [$at + $prefix, $at + $matched - $suffix, substr($replacement, $prefix, $written - $prefix - $suffix)];
    }

    /**
     * One custom pattern over the text; null when the engine failed.
     *
     * A decoded layer may hold bytes that are not UTF-8 (`caf%E9`, a
     * Latin-1 address): a pattern written with `/u` cannot read them, so it
     * reads the layer with each such byte written `?`, the same length, and
     * its masks are put in the layer itself. The text as written keeps the
     * old verdict: unreadable, withheld.
     *
     * @return array{0: string, 1: array<int, array{0: int, 1: int, 2: string}>}|null
     */
    private function applyCustom(string $text, string $label, string $pattern, int $depth): ?array
    {
        $subject = $depth > 0 && self::isUnicode($pattern) && preg_match('//u', $text) !== 1
            ? self::scrubUtf8($text)
            : $text;

        $mask = $this->mask($label);
        $edits = [];

        $replaced = @preg_replace_callback($pattern, function (array $m) use (&$edits, $mask): string {
            if ($m[0][0] !== $mask) {
                $edits[] = [$m[0][1], $m[0][1] + strlen($m[0][0]), $mask];
            }

            return $mask;
        }, $subject, -1, $count, PREG_OFFSET_CAPTURE);

        // The pattern compiled (the constructor checked), so a null here is
        // the engine giving up on this value: a backtrack or recursion limit,
        // or bytes that are not the UTF-8 the pattern asked for.
        if (! is_string($replaced)) {
            return null;
        }

        return [$subject === $text ? $replaced : self::rewrite($text, $edits), $edits];
    }

    /**
     * Whether a pattern carries the `u` modifier, read after its closing
     * delimiter (a bracket pair closes on its counterpart).
     */
    private static function isUnicode(string $pattern): bool
    {
        $open = $pattern[0] ?? '';
        $close = ['(' => ')', '{' => '}', '[' => ']', '<' => '>'][$open] ?? $open;
        $at = strrpos($pattern, $close);

        return $at !== false && $at > 0 && str_contains(substr($pattern, $at + 1), 'u');
    }

    /**
     * The text with each byte that is not part of a UTF-8 character written
     * `?`: same length, same positions.
     */
    private static function scrubUtf8(string $text): string
    {
        $out = '';

        for ($i = 0, $length = strlen($text); $i < $length;) {
            $byte = ord($text[$i]);
            $size = match (true) {
                $byte < 0x80 => 1,
                $byte >= 0xC2 && $byte <= 0xDF => 2,
                $byte >= 0xE0 && $byte <= 0xEF => 3,
                $byte >= 0xF0 && $byte <= 0xF4 => 4,
                default => 0,
            };

            if ($size === 1 || ($size > 1 && preg_match('//u', substr($text, $i, $size)) === 1 && $i + $size <= $length)) {
                $out .= substr($text, $i, max($size, 1));
                $i += max($size, 1);

                continue;
            }

            $out .= '?';
            $i++;
        }

        return $out;
    }

    /**
     * A long text in pieces no pattern straddles.
     *
     * Every shape but the key block sits on one line, so a piece ends on the
     * last line break of the window; a window with no line break ends on its
     * last space, and one with no space on its last byte outside the alphabet
     * every token is written in, the backslash of an escaped slash (`\/`, as
     * json_encode writes it) included, and so is every character a
     * percent-encoded value is written with (`~ ! $ ' ( ) * , ;`), or a DSN
     * password written `pa;ss` inside an encoded value was cut in half. A
     * window with none of those is one run of token characters, a blob, and
     * is cut where it is: the half of a token on either side of that cut is
     * not a token any more.
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

                if ($cut === false && preg_match('~[^A-Za-z0-9_+/=.:@\~!$\'()*,;%\\\-](?=[A-Za-z0-9_+/=.:@\~!$\'()*,;%\\\-]*+$)~D', $window, $m, PREG_OFFSET_CAPTURE) === 1) {
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
     * One built-in pattern over the text, and where it put its masks. Null
     * when the engine failed, which the caller turns into UNSCANNABLE; the
     * old behaviour, handing the text back as it came, sent precisely the
     * value nothing had read.
     *
     * @return array{0: string, 1: array<int, array{0: int, 1: int, 2: string}>}|null
     */
    private function apply(string $text, string $name, int $depth, ?string $parent): ?array
    {
        if (! self::mightMatch($name, $text)) {
            return [$text, []];
        }

        if ($name === 'url_password') {
            return $this->applyUrlPassword($text, $depth, $parent);
        }

        if ($name === 'card') {
            return $this->applyCard($text);
        }

        $edits = [];

        $replaced = @preg_replace_callback(
            $this->pattern($name),
            function (array $m) use ($name, &$edits): string {
                $groups = array_map(fn (array $group): string => $group[0], $m);
                $replacement = $this->replacement($name, $groups);
                self::edit($edits, $m[0][1], $m[0][0], $replacement);

                return $replacement;
            },
            $text,
            -1,
            $count,
            PREG_OFFSET_CAPTURE,
        );

        return is_string($replaced) ? [$replaced, $edits] : null;
    }

    /**
     * Whether a text holds what a shape needs before it can match: a test of
     * a few bytes that spares most strings the pattern itself. It never
     * answers no where the pattern could match.
     */
    private static function mightMatch(string $name, string $text): bool
    {
        return match ($name) {
            'private_key' => str_contains($text, 'PRIVATE KEY'),
            'jwt' => str_contains($text, 'eyJ'),
            'stripe' => str_contains($text, '_live_') || str_contains($text, '_test_') || str_contains($text, 'whsec_'),
            'aws' => str_contains($text, 'AKIA') || str_contains($text, 'ASIA'),
            'aws_secret' => stripos($text, '[redacted:aws]') !== false || stripos($text, 'aws_secret') !== false,
            'github' => str_contains($text, 'gh') || str_contains($text, 'github_pat_'),
            'gitlab' => str_contains($text, 'gl') && str_contains($text, '-'),
            'slack' => str_contains($text, 'xox') || str_contains($text, 'xapp-') || str_contains($text, 'hooks.slack.com'),
            'app_key' => str_contains($text, 'base64:'),
            'project_key' => str_contains($text, 'lm_'),
            'aws_presigned' => stripos($text, 'X-Amz-Signature') !== false,
            'url_password' => str_contains($text, ':/') || str_contains($text, ':\\/'),
            'email' => str_contains($text, '@'),
            'iban', 'card', 'nir' => strpbrk($text, '0123456789') !== false,
            'phone' => str_contains($text, '0') || str_contains($text, '+'),
            default => true,
        };
    }

    /**
     * The card numbers of a text: every run of digit groups (one space or
     * hyphen between two groups) is read, and in it the spans that are a
     * card are masked.
     *
     * A single pattern used to take thirteen to nineteen digits greedily
     * and give up when Luhn refused them, never retrying: a card followed by
     * its expiry (`4111 1111 1111 1111 12/27`) or preceded by a phone number
     * was one run that failed and left in clear, and a second pass, once the
     * phone was masked, found the card the first had missed. So the whole
     * run is tried when it holds thirteen to nineteen digits, as before, and
     * failing that every span of whole groups laid out as a card is (groups
     * of four, the last shorter; American Express 4-6-5, Diners 4-6-4; or
     * one group of thirteen to nineteen), the longest first from each group,
     * and only one that passes Luhn is masked. A layout rather than any span,
     * since Luhn accepts one sequence in ten and a long list of digit groups
     * holds many spans.
     *
     * @return array{0: string, 1: array<int, array{0: int, 1: int, 2: string}>}|null
     */
    private function applyCard(string $text): ?array
    {
        if (@preg_match_all('/(?<!\d)\d++(?:[ \-]\d++)*+/', $text, $runs, PREG_OFFSET_CAPTURE) === false) {
            return null;
        }

        $edits = [];
        $mask = $this->mask('card');

        foreach ($runs[0] as [$run, $at]) {
            $plain = preg_replace('/\D/', '', $run) ?? '';

            if (strlen($plain) < 13) {
                continue;
            }

            if (strlen($plain) <= 19 && $this->passesLuhn($plain)) {
                $edits[] = [$at, $at + strlen($run), $mask];

                continue;
            }

            preg_match_all('/\d++/', $run, $found, PREG_OFFSET_CAPTURE);
            $groups = $found[0];
            $count = count($groups);

            for ($from = 0; $from < $count; $from++) {
                // Every layout opens on a group of four or is one group of
                // thirteen to nineteen: any other first group starts no card,
                // and reading on from it cost seconds on a run of `1 1 1`.
                $first = strlen($groups[$from][0]);

                if ($first !== 4 && ($first < 13 || $first > 19)) {
                    continue;
                }

                $digits = '';
                $sizes = [];
                $best = null;

                for ($to = $from; $to < $count && strlen($digits) + strlen($groups[$to][0]) <= 19; $to++) {
                    $digits .= $groups[$to][0];
                    $sizes[] = strlen($groups[$to][0]);

                    if (strlen($digits) >= 13 && self::laidOutAsCard($sizes) && $this->passesLuhn($digits)) {
                        $best = $to;
                    }
                }

                if ($best !== null) {
                    $start = $at + $groups[$from][1];
                    $edits[] = [$start, $at + $groups[$best][1] + strlen($groups[$best][0]), $mask];
                    $from = $best;
                }
            }
        }

        return [self::rewrite($text, $edits), $edits];
    }

    /**
     * Whether digit groups of these sizes are laid out as a card number.
     *
     * @param  array<int, int>  $sizes
     */
    private static function laidOutAsCard(array $sizes): bool
    {
        if (count($sizes) === 1) {
            return $sizes[0] >= 13 && $sizes[0] <= 19;
        }

        if ($sizes === [4, 6, 5] || $sizes === [4, 6, 4]) {
            return true;
        }

        $last = array_pop($sizes);

        return $last >= 1 && $last <= 4 && array_unique($sizes) === [4];
    }

    /**
     * The `url_password` pattern over the text, one address at a time.
     *
     * The password runs to the last `@` the text allows, which in a decoded
     * query string can be the `@` of an email in a later parameter
     * (`?dsn=redis%3A%2F%2Fu%3Apw%40cache&email=a%40b.fr` read decoded): the
     * whole query went into the mask. So, in a decoded layer, when a
     * password crosses a `&name=` pair whose `&` was WRITTEN (an encoded
     * `%26` is ENCODED_AMPERSAND, part of the value), and what precedes the
     * pair is an address that was written encoded (it does not appear as
     * such in the text one level up), only that address is masked and the
     * reading goes on from the pair. Everywhere else, in doubt, the whole
     * password goes: `redis://default:Xy@9&k=Q7rT2@cache` may be one
     * password, and masking too much costs a readable address where
     * masking too little sends a secret. Null when the engine failed.
     *
     * @return array{0: string, 1: array<int, array{0: int, 1: int, 2: string}>}|null
     */
    private function applyUrlPassword(string $text, int $depth, ?string $parent): ?array
    {
        $pattern = $this->pattern('url_password');
        $out = '';
        $edits = [];
        $offset = 0;

        while (true) {
            $found = @preg_match($pattern, $text, $m, PREG_OFFSET_CAPTURE, $offset);

            if ($found === false) {
                return null;
            }

            if ($found === 0) {
                return [$out.substr($text, $offset), $edits];
            }

            [$whole, $start] = $m[0];
            $prefix = $m[1][0];
            $password = $m[2][0];
            $out .= substr($text, $offset, $start - $offset);

            // An address that ends on a `&` was chosen because the longest
            // reading failed further on: when an `@` still follows before
            // the next blank, the password may run to it
            // (`redis://default:Xy@9&k=Q7rT2@cache.internal:6379~`), and in
            // doubt it does.
            $after = $start + strlen($whole) + strlen($m[3][0]);

            if (($text[$after] ?? '') === '&') {
                $rest = substr($text, $after, strcspn($text, " \t\n\r\"'?\\", $after));
                $last = strrpos($rest, '@');

                if ($last !== false) {
                    $password = substr($text, $start + strlen($prefix), $after + $last - $start - strlen($prefix));
                    $whole = $prefix.$password.'@';
                }
            }

            // A password that opens on a mask and runs past it has crossed
            // into the next address (`redis://u:sk_live_...@a,redis://v:pw@b`:
            // the token was masked a step earlier, and the password ran on to
            // the last `@`): keep the mask, read on after it, so the next
            // address is read as an address. The old rule kept the whole
            // match as it was, which sent the second password in clear.
            if (preg_match('~^\[redacted:[^\]\[\n]*\]~', $password, $lead) === 1 && strlen($lead[0]) < strlen($password)) {
                $keep = strlen($prefix) + strlen($lead[0]);
                $out .= substr($text, $start, $keep);
                $offset = $start + $keep;

                continue;
            }

            if ($depth > 0 && $parent !== null && ! str_starts_with($password, '[redacted:')
                && preg_match('~&[^\s&=@/]*+=~', $password, $pair, PREG_OFFSET_CAPTURE) === 1) {
                $head = substr($text, $start, strlen($prefix) + $pair[0][1]);

                if (! str_contains($parent, $head)) {
                    $masked = $this->applyUrlPassword($head, $depth, $parent);

                    if ($masked === null) {
                        return null;
                    }

                    if ($masked[0] !== $head) {
                        foreach ($masked[1] as [$from, $to, $replacement]) {
                            $edits[] = [$start + $from, $start + $to, $replacement];
                        }

                        $out .= $masked[0];
                        $offset = $start + strlen($head);

                        continue;
                    }
                }
            }

            $replacement = $this->replacement('url_password', [$whole, $prefix, $password]);
            self::edit($edits, $start, $whole, $replacement);
            $out .= $replacement;
            $offset = $start + strlen($whole);
        }
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

            // The signature of a presigned S3 address (SigV4, query form):
            // sixty-four hex digits after `X-Amz-Signature=`. The name stays,
            // the digits go; host, path and `X-Amz-Credential` stay readable.
            'aws_presigned' => '~(?<![A-Za-z0-9])((?i:X-Amz-Signature)=)[0-9a-fA-F]{64}(?![0-9a-fA-F])~',

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
            // the authority from one in a path or a query: an `&` (an
            // address passed as a parameter ends there once the query is
            // decoded, `?dsn=redis://u:pw@cache&x=1`; an encoded one reads
            // as ENCODED_AMPERSAND), and the punctuation a sentence puts
            // around an address: `)`, `,`, `;`, `>`, a backquote, a final
            // `.`. A password that runs across a `&name=` pair is read again
            // by applyUrlPassword(). Every run is bounded (a scheme of 32, a
            // user and a password of 256, a host of 253, a port of five
            // digits): unbounded, a text of `redis://u:aa@!` repeated cost
            // 615 ms at 64 KB, every start retrying every end. The user may
            // already be a mask (a token written there was labelled a step
            // earlier), whose own colon must not be read as the separator.
            'url_password' => '~(?<![A-Za-z0-9+.\-])([a-z][a-z0-9+.\-]{0,31}:(?:\\\\?/){2}(?:\[redacted:[a-z_]+\]|[^\s/:"\'\\\\]{0,256}):)((?:(?!\d+/)[^\s"\'?\\\\]{1,256}|[^\s"\'?/\\\\]{1,256}))@(?=([A-Za-z0-9._\-\[\]]{1,253}(?::\d{1,5})?)(?:[\s/?#&"\'),;>`\x00]|%[0-9A-Fa-f]{2}|\.(?:\s|$)|\\\\/|$))~i',

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
        if (in_array($name, ['slack', 'aws_secret', 'aws_presigned'], true) && isset($m[1]) && $m[1] !== '') {
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
