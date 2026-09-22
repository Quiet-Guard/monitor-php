# Changelog

All notable changes to `quiet-guard/monitor-php`.

## v0.3.1

### Security

- A header spelled with hyphens is masked like its underscore spelling.
  Symfony's request, which Laravel's extends, names every header lower-cased
  with hyphens, so the password of an HTTP Basic request arrived as
  `php-auth-pw` while the lists write `php_auth_pw`, and travelled in clear;
  `x-api-key` got past `api_key` the same way. A hyphen and an underscore are
  one character now when a key or a query-string name is matched.
- A name with a separator inside it is also found in a key written without
  one. Supabase and Kong send their key as an `apikey` header and a form field
  is `apiKey`, which hold no `api_key`, so they travelled in clear. A
  configured name that carries a hyphen or an underscore between two of its
  characters is now also looked for, without them, in a key or a query-string
  name stripped of its own. A name with no separator matches as before, and
  one that starts or ends with a separator keeps its spelling: WordPress's
  `db_` written as `db` would mask `feedback`.
- `Scrubber::scrub()` opens a JSON object or array written as a string, such
  as Livewire's `components.*.snapshot`, the state of a component with a typed
  password in it. The scrubber only descended into arrays, so the string
  travelled as it came. It is decoded, masked by key and written back now;
  handed back byte for byte when nothing inside matched, and replaced whole
  with the mask when it held a secret and cannot be written back. A string
  that opens like JSON and does not decode is replaced whole with the mask
  when a quoted name followed by `:` in it matches: a client that masks
  values by shape over the whole payload turns a sixteen-digit number that
  passes Luhn into `[redacted:card]`, the snapshot is no longer JSON, and the
  password beside that number travelled with it.
- A string that starts with an absolute `http(s)` URL is masked as an address
  (`Scrubber::scrubUrl()`, public): the values of the query-string parameters
  and of the fragment's `name=value` pairs whose name matches, and every path
  segment made of forty letters or digits in a row, whatever the list says. A
  password reset link carries its token in the query or in the path
  (`/reset-password/{token}` in Breeze, Fortify and Jetstream), and a context
  value holding one, Symfony's `request.url` for instance, carried it in
  clear. A number, a slug, a UUID or a ULID stays; the scheme, the host, the
  port and the user of a userinfo travel as they came, its password is
  masked (`user:%5Bscrubbed%5D@`), since a URL typed into a form field, a
  webhook or a DSN, carries it; a relative address is not reached.
  The text after the URL is handed back as it came, except a pair opened by
  `&`, `?` or `#` whose name matches.
- A source line that gives a value to an array index named in quotes is masked
  whole. A secret hardcoded into an array (`$config['password'] = '...'`,
  `$headers['Authorization'] = 'Bearer ...'`) travelled in clear in a snippet,
  since the `']` between the name and the `=` matched none of the value
  shapes. A comparison with such an index counts as a value, as it does for a
  variable, since its other side may be the secret itself; an index that is a
  variable (`$data[$key] = ...`) is not read as a name.

### Fixed

- A snippet line that calls a static method keeps its context. The first colon
  of `::` read as a key separator, so any line naming a needle before one
  (`Auth::user()`, `TokenMismatchException::expired()`) was masked whole, the
  line of the throw included. `::` is a scope now.
- A term is tried in its other spelling in a source line when a hyphen or an
  underscore sits inside it, between two letters or digits, so a hardcoded
  `'php-auth-pw' => '...'` is masked under `php_auth_pw`. The line itself is
  never rewritten, and a term that starts or ends with a separator keeps its
  one spelling, a configured one and a word of `Scrubber::LINE_NEEDLES` alike:
  the other one of WordPress's `db_` starts an ordinary word (`'db-new'`), the
  other one of `sk_` ends one (`'disk-usage'`).

### Changed

- `Reporter::sendLogs()` reaches the message of a log as well as its context,
  since the strings of the batch are opened: when a message starts with a URL
  or is JSON, the values it carries are masked by the rules of any other
  string, and the rest of its text is kept.

## v0.3.0

### Added

- Stack traces start at the throw site: the exception's own file and line
  travel as frame zero, the way Laravel's exception page shows them, since
  PHP's `getTrace()` starts at the caller. `trace_limit` counts that frame.
- Application frames carry a source snippet (`code.start`, `code.lines`): the
  five lines on each side of the frame's line, read from the file that ran,
  cut at 500 characters a line, at most ten frames a report, never a
  dependency's (`SourceSnippet`). `Config::$codeSnippets` (default true)
  switches it off. A line that names a secret (a scrub key, or one of
  `Scrubber::LINE_NEEDLES`: `key`, `auth`, `credential`, `salt`, `private`,
  `dsn`, `bearer`) AND gives it a value is masked whole, because source is
  where a hardcoded secret lives (`Scrubber::scrubLines()`); a line that only
  uses the name stays. `wp-config.php`, `.env*`, `wp-includes/` and
  `wp-admin/` never carry a snippet, and `Cut::payload()` bounds snippet
  lines again after redaction, which lengthens them.

## v0.2.2

### Fixed

- `Config` resolves and normalises the server address itself: an absent value
  becomes the hosted service (`Config::HOSTED_URL`), and a trailing `/api` or
  `/api/vN` supplied by the caller is stripped, since every path carries its
  own. `Reporter` held a second copy of that stripping rule and now reads the
  normalised value. `isConfigured()` asks for the key alone, the only thing
  that cannot be guessed.

## v0.2.1

### Fixed

- A refused report is no longer silent. Any non-2xx answer is logged through the
  PSR-3 logger with the status and the address it was sent to. The previous
  version could only speak from a `catch`, and the bundled cURL client never
  throws, so an invalid key, a suspended account and a refused payload all
  produced nothing at all.
- The configured server address is trimmed, and an address that already ends in
  `/api` or `/api/v1` is accepted. Every method appends `/api/v1` itself, so
  supplying the API address, which is how the setting is often read, used to
  answer 404 on every call and look exactly like a wrong key.
- Exception messages over 8192 characters, class names over 255, file paths over
  1024 and release strings over 255 are trimmed with a visible marker instead of
  being refused by the server and lost. The trim is the last thing applied
  before sending, after masking, because masking replaces a value with a longer
  label and a payload trimmed before it could come back over the limit.
- French social security numbers from Corsica are masked. The pattern accepted
  `2A` and `2B` as a department while the check digit was computed on digits
  alone, which left fourteen characters where fifteen are required, so the check
  always failed and the number travelled in clear.
- An encrypted backup cut short by a full disk now fails where it is written.
  Every write is compared against what it was asked to write, and the closing
  flush is checked, on both the encrypting and the decrypting side. A truncated
  archive used to be produced, uploaded and reported as a success, and found out
  months later at restore time.

### Changed

- `ErrorHandler::register()` reports userland fatals and recoverable errors by
  default rather than every notice and warning, reports one site once, and stops
  at twenty reports. It forwarded every severity as one blocking HTTP request
  each, so a single warning inside a loop was hundreds of requests in one page
  load. Pass `E_ALL` as the second argument to restore the previous reach, and a
  count as the third to change the ceiling. The two counters are per
  registration: a host that registers once per request gets a per-request
  budget, and a long-running process should register per unit of work.

### Added

- `Support\Cut`, the one definition of the server's field limits, usable
  directly when you build a payload yourself.
