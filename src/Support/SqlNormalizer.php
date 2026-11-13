<?php

namespace QuietGuard\Monitor\Support;

/**
 * The shape of an SQL statement with every value taken out.
 *
 * Laravel hands over its SQL with `?` for the bindings, but not always: an
 * eager load writes integer keys in line (`whereIntegerInRaw`), and `whereRaw`,
 * `DB::raw` or a hand-written statement carry whatever their author wrote. The
 * performance measurements send this shape, never a value, so the shape is
 * built by a scanner rather than a sequence of regular expressions: a string
 * escape, a comment or an unterminated quote read wrongly by one expression
 * would let the rest of the statement out in clear.
 *
 * One implementation, used by the client before anything is written or sent
 * and run again by the server, which trusts no client and alone computes the
 * hash. Over-masking costs nothing here: a lost identifier is a less precise
 * screen, a leaked value is personal data on our disks.
 *
 * Known limit, stated wherever this is documented: a value carried by a table,
 * schema or alias name (`client_dupont.users`) is a name to the scanner.
 */
final class SqlNormalizer
{
    public const MAX_LENGTH = 500;

    /** Prefixes that turn the quoted string after them into a literal (X'..', N'..', E'..', B'..', U&'..'). */
    private const STRING_PREFIXES = ['x', 'b', 'e', 'n', 'u&'];

    public static function normalize(string $sql): string
    {
        $out = '';
        $length = strlen($sql);
        $i = 0;

        while ($i < $length) {
            $char = $sql[$i];
            $next = $sql[$i + 1] ?? '';

            // Comments: dropped whole. An unterminated block comment drops the rest.
            if ($char === '-' && $next === '-') {
                $i = self::skipToLineEnd($sql, $i);

                continue;
            }

            if ($char === '#') {
                $i = self::skipToLineEnd($sql, $i);

                continue;
            }

            if ($char === '/' && $next === '*') {
                $end = strpos($sql, '*/', $i + 2);
                $i = $end === false ? $length : $end + 2;
                $out .= ' ';

                continue;
            }

            // Quoted strings, single or double (MySQL reads "..." as a string by
            // default; Laravel quotes identifiers with backticks, kept below).
            if ($char === "'" || $char === '"') {
                $out = self::dropLiteralPrefix($out).'?';
                $i = self::skipQuoted($sql, $i, $char);

                continue;
            }

            // Dollar-quoted strings: $$...$$ or $tag$...$tag$.
            if ($char === '$' && preg_match('/\G\$([A-Za-z_][A-Za-z0-9_]*)?\$/', $sql, $match, 0, $i) === 1) {
                $end = strpos($sql, $match[0], $i + strlen($match[0]));
                $out .= '?';
                $i = $end === false ? $length : $end + strlen($match[0]);

                continue;
            }

            // Backtick identifiers stay as written (a doubled backtick escapes one).
            if ($char === '`') {
                $end = $i + 1;

                while ($end < $length) {
                    if ($sql[$end] === '`') {
                        if (($sql[$end + 1] ?? '') === '`') {
                            $end += 2;

                            continue;
                        }

                        break;
                    }

                    $end++;
                }

                $out .= substr($sql, $i, $end - $i + 1);
                $i = $end + 1;

                continue;
            }

            // Numbers that are not part of an identifier: 42, 3.14, 1e10, 0x1F, 0b101.
            if ((ctype_digit($char) || ($char === '.' && ctype_digit($next))) && ! self::endsWithIdentifier($out)) {
                $i = self::skipNumber($sql, $i);
                $out .= '?';

                continue;
            }

            if (ctype_space($char)) {
                if ($out !== '' && ! str_ends_with($out, ' ')) {
                    $out .= ' ';
                }

                $i++;

                continue;
            }

            $out .= $char;
            $i++;
        }

        $out = trim(preg_replace('/ {2,}/', ' ', $out) ?? $out);

        // A list of placeholders is one placeholder, whatever its length: an eager
        // load of 3 keys and one of 300 are the same statement.
        $out = preg_replace('/\(\s*\?(?:\s*,\s*\?)+\s*\)/', '(...?)', $out) ?? $out;
        // INSERT ... VALUES (..), (..), (..) is one row's shape.
        $out = preg_replace('/(\((?:[^()]|\([^()]*\))*\))(?:\s*,\s*\((?:[^()]|\([^()]*\))*\))+/', '$1', $out) ?? $out;

        return mb_strlen($out) > self::MAX_LENGTH ? mb_substr($out, 0, self::MAX_LENGTH) : $out;
    }

    private static function skipToLineEnd(string $sql, int $i): int
    {
        $end = strpos($sql, "\n", $i);

        return $end === false ? strlen($sql) : $end;
    }

    /** Index just past the closing quote; the end of the text when there is none. */
    private static function skipQuoted(string $sql, int $start, string $quote): int
    {
        $length = strlen($sql);
        $i = $start + 1;

        while ($i < $length) {
            $char = $sql[$i];

            if ($char === '\\') {
                $i += 2;

                continue;
            }

            if ($char === $quote) {
                if (($sql[$i + 1] ?? '') === $quote) {
                    $i += 2;

                    continue;
                }

                return $i + 1;
            }

            $i++;
        }

        return $length;
    }

    private static function skipNumber(string $sql, int $i): int
    {
        if (preg_match('/\G(?:0[xX][0-9A-Fa-f]+|0[bB][01]+|(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?)/', $sql, $match, 0, $i) === 1) {
            return $i + strlen($match[0]);
        }

        return $i + 1;
    }

    /** Whether the output ends inside an identifier, which makes a digit part of a name (t1, col2). */
    private static function endsWithIdentifier(string $out): bool
    {
        if ($out === '') {
            return false;
        }

        $last = $out[strlen($out) - 1];

        return ctype_alnum($last) || $last === '_' || $last === '$' || ord($last) >= 0x80;
    }

    /** Remove an X / N / E / B / U& prefix that belongs to the literal about to be replaced. */
    private static function dropLiteralPrefix(string $out): string
    {
        foreach (self::STRING_PREFIXES as $prefix) {
            $length = strlen($prefix);

            if (strlen($out) >= $length && strtolower(substr($out, -$length)) === $prefix) {
                $before = substr($out, 0, -$length);

                if ($before === '' || ! self::endsWithIdentifier($before)) {
                    return $before;
                }
            }
        }

        return $out;
    }
}
