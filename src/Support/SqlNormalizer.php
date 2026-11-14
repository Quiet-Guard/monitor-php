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
 * Every ambiguity resolves towards masking: a backslash inside a string, an
 * unterminated quote, backtick or comment masks the rest of the statement, and
 * reading `--`, a nested comment or a `$` the wrong way only removes text.
 *
 * Known limit, stated wherever this is documented: a value carried by a table,
 * schema or alias name (`client_dupont.users`) is a name to the scanner.
 */
final class SqlNormalizer
{
    public const MAX_LENGTH = 500;

    /** Prefixes that turn the quoted string after them into a literal (X'..', N'..', E'..', B'..', U&'..'). */
    private const STRING_PREFIXES = ['x', 'b', 'e', 'n', 'u&'];

    /** Every character the scanner acts on; anything else is copied as written. */
    private const SIGNIFICANT = "'\"`$-#/.0123456789 \t\n\r\v\f";

    /**
     * The drivers whose grammar quotes identifiers with double quotes rather
     * than backticks: on them "users" is a table, not a value.
     */
    public const DOUBLE_QUOTED_IDENTIFIER_DRIVERS = ['pgsql', 'sqlite', 'sqlsrv'];

    /**
     * @param  bool  $doubleQuotedIdentifiers  true for Postgres, SQLite and SQL Server,
     *                                         whose Laravel grammars write `"users"."id"`;
     *                                         false (MySQL, MariaDB) reads "..." as a string
     */
    public static function normalize(string $sql, bool $doubleQuotedIdentifiers = false): string
    {
        $out = '';
        $length = strlen($sql);
        $i = 0;

        while ($i < $length) {
            // A run of characters that start nothing is copied in one go.
            $run = strcspn($sql, self::SIGNIFICANT, $i);

            if ($run > 0) {
                $out .= substr($sql, $i, $run);
                $i += $run;

                continue;
            }

            $char = $sql[$i];
            $next = $sql[$i + 1] ?? '';

            // Comments: dropped whole. An unterminated block comment drops the
            // rest. Dialects disagree on where a comment ends (MySQL wants a
            // space after --, Postgres nests /* */ and ends -- at \r): a comment
            // that holds a quote, a nested opener or a \r may not be one for
            // the database, so the rest of the statement goes.
            if (($char === '-' && $next === '-') || $char === '#' || ($char === '/' && $next === '*')) {
                $block = $char === '/';
                $end = $block ? strpos($sql, '*/', $i + 2) : strpos($sql, "\n", $i);
                $stop = $end === false ? $length : $end + ($block ? 2 : 0);
                $body = substr($sql, $i + ($block ? 2 : 1), $stop - $i - ($block ? 4 : 1));

                if (strpbrk($body, "'\"`$\r") !== false || ($block && str_contains($body, '/*'))) {
                    $out .= ' ?';

                    break;
                }

                $out .= $block ? ' ' : '';
                $i = $stop;

                continue;
            }

            // Quoted strings, single or double (MySQL reads "..." as a string by
            // default; Laravel quotes identifiers with backticks, kept below).
            if ($char === "'" || ($char === '"' && ! $doubleQuotedIdentifiers)) {
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

            // Quoted identifiers stay as written (a doubled quote escapes one):
            // backticks always, double quotes on the drivers that use them so.
            if ($char === '`' || $char === '"') {
                $end = strpos($sql, $char, $i + 1);

                // A doubled quote escapes one and does not close.
                while ($end !== false && ($sql[$end + 1] ?? '') === $char) {
                    $end = strpos($sql, $char, $end + 2);
                }

                // Never closed: what follows cannot be told from a value, so it goes.
                if ($end === false) {
                    $out .= '?';
                    $i = $length;

                    continue;
                }

                $token = substr($sql, $i, $end - $i + 1);
                $i = $end + 1;

                // SQLite falls back to reading "..." as a string when no
                // column has that name, and SQL Server does with
                // QUOTED_IDENTIFIER off: a double-quoted token is kept only
                // when it looks like a name and stands where a name stands.
                $out .= $char === '"' && ! self::isIdentifierToken($token, $out, substr($sql, $i, 24)) ? '?' : $token;

                continue;
            }

            // Numbers that are not part of an identifier: 42, 3.14, 1e10, 0x1F, 0b101.
            if ((ctype_digit($char) || ($char === '.' && ctype_digit($next))) && ! self::endsWithIdentifier($out)) {
                $i = self::skipNumber($sql, $i);
                // Postgres 16 writes 1_000_000 and 0o17: whatever is glued to
                // the number belongs to it.
                $i += strspn($sql, 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_', $i);
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

        if (str_contains($out, '  ')) {
            $out = preg_replace('/ {2,}/', ' ', $out) ?? $out;
        }

        $out = trim($out);

        // A list of placeholders is one placeholder, whatever its length: an eager
        // load of 3 keys and one of 300 are the same statement.
        $out = preg_replace('/\(\s*\?(?:\s*,\s*\?)+\s*\)/', '(...?)', $out) ?? $out;
        // INSERT ... VALUES (..), (..), (..) is one row's shape.
        if (preg_match('/\)\s*,\s*\(/', $out) === 1) {
            $out = preg_replace('/(\((?:[^()]|\([^()]*\))*\))(?:\s*,\s*\((?:[^()]|\([^()]*\))*\))+/', '$1', $out) ?? $out;
        }

        return mb_strlen($out) > self::MAX_LENGTH ? mb_substr($out, 0, self::MAX_LENGTH) : $out;
    }

    /**
     * Whether a double-quoted token reads as a name. SQLite reads "..." as a
     * string when no column has that name, SQL Server does with
     * QUOTED_IDENTIFIER off, so a token is kept only where Laravel's grammars
     * put names: beside a dot, after FROM, JOIN, INTO, UPDATE, TABLE, ON, BY,
     * AS, SELECT or DISTINCT, or right before a comparison. Anything else
     * (a function argument, the right of an operator) is masked.
     */
    private static function isIdentifierToken(string $token, string $before, string $after): bool
    {
        if (preg_match('/^"[A-Za-z_][A-Za-z0-9_$]{0,63}"$/', $token) !== 1) {
            return false;
        }

        $before = rtrim($before);

        return str_ends_with($before, '.')
            || str_starts_with(ltrim($after), '.')
            || preg_match('/\b(?:from|join|into|update|table|on|by|as|select|distinct)$/i', $before) === 1
            || (preg_match('/^\s*(?:[=<>!]|(?:not\s+)?(?:in|is|i?like|between)\b)/i', $after) === 1
                && preg_match('/(?:[=<>!(,]|\b(?:i?like|between|then|else|when|case|coalesce|is|in|values|limit|offset|match|glob|regexp))$/i', $before) !== 1);
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

            // A backslash escapes the quote in MySQL and not in SQLite or
            // Postgres ('C:\' is a whole string there). Reading it the wrong
            // way shifts every quote after it and lets the next value out, so
            // the rest of the statement is masked instead of guessed.
            if ($char === '\\') {
                return $length;
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
