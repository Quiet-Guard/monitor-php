<?php

namespace QuietGuard\Monitor\Support;

/**
 * Masks personal data by the shape of the VALUE, wherever it sits.
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
 * is not an IBAN unless it passes mod 97.
 *
 * Every replacement names what it hid. "User [redacted:email] not found" still
 * says what went wrong; "User [redacted] not found" says less for no extra
 * safety. The tag also tells a value match apart from a Scrubber key match.
 */
class ValueRedactor
{
    /**
     * Built-in patterns, in the order they are applied.
     *
     * Order matters where shapes overlap: an IBAN before a card so its digits
     * are not read as one, a French social security number before a card so the
     * fifteen digits that occasionally satisfy Luhn are labelled for what they
     * are, and a card before a phone so a sixteen digit run is not partly eaten
     * by a ten digit pattern.
     */
    public const PATTERNS = ['email', 'iban', 'nir', 'card', 'phone'];

    /**
     * Strings longer than this are left alone. A payload that big is a dump or
     * a serialized blob, not a message, and scanning it in the exception path
     * of a production request costs more than it protects.
     */
    private const MAX_LENGTH = 65536;

    /** @var array<int, string> */
    private array $enabled;

    /** @var array<string, string> */
    private array $custom;

    /**
     * @param  array<int, string>  $enabled  built-in pattern names to apply
     * @param  array<string, string>  $custom  label => PCRE pattern, applied last
     */
    public function __construct(array $enabled = self::PATTERNS, array $custom = [])
    {
        $this->enabled = array_values(array_intersect(self::PATTERNS, $enabled));
        $this->custom = $custom;
    }

    /**
     * Mask every recognised value in a string.
     *
     * Never throws and never returns null: a redaction failure must not be the
     * reason an application stops reporting its errors. On any failure the
     * input is returned unchanged, which is the same exposure as before this
     * class existed rather than a new one.
     */
    public function redact(string $text): string
    {
        if ($text === '' || strlen($text) > self::MAX_LENGTH) {
            return $text;
        }

        foreach ($this->enabled as $name) {
            $text = $this->apply($text, $name);
        }

        foreach ($this->custom as $label => $pattern) {
            $replaced = @preg_replace($pattern, $this->mask((string) $label), $text);

            if (is_string($replaced)) {
                $text = $replaced;
            }
        }

        return $text;
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
            $key = is_string($key) ? $this->redact($key) : $key;

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

    private function apply(string $text, string $name): string
    {
        $replaced = @preg_replace_callback(
            $this->pattern($name),
            fn (array $m): string => $this->confirms($name, $m[0]) ? $this->mask($name) : $m[0],
            $text,
        );

        return is_string($replaced) ? $replaced : $text;
    }

    private function pattern(string $name): string
    {
        return match ($name) {
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
     * Second opinion for the shapes that carry a checksum.
     */
    private function confirms(string $name, string $match): bool
    {
        return match ($name) {
            'card' => $this->passesLuhn(preg_replace('/\D/', '', $match) ?? ''),
            'iban' => $this->passesMod97(preg_replace('/\s/', '', $match) ?? ''),
            'nir' => $this->passesNirKey(preg_replace('/\D/', '', $match) ?? ''),
            default => true,
        };
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
