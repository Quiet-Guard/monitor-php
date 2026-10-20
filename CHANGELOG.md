# Changelog

All notable changes to `quiet-guard/monitor-php`.

## v0.6.0 (unreleased)

### Security

- `ValueRedactor` masks credentials by their shape, wherever they sit (an
  exception message, a context field of any name, a code snippet line, a log),
  on by default: Stripe keys (`sk_live_`, `sk_test_`, `rk_live_`, `rk_test_`,
  `whsec_`), AWS access key ids (`AKIA`, `ASIA`) and the secret key only
  where it is known for what it is (within eighty characters after an id, or
  under `aws_secret_access_key`), GitHub tokens (`ghp_`, `gho_`, `ghu_`,
  `ghs_`, `ghr_`, `github_pat_`), GitLab tokens (`glpat-`, `glrt-`, `gldt-`,
  `gloas-`, `glptt-`, `glffct-`, `glimt-`, `glagent-`, `glcbt-`, `glsoat-`),
  Slack tokens (`xox?-`, `xapp-`) and the path of a `hooks.slack.com`
  webhook, JWTs (header decoded and parsed), private key blocks
  (`-----BEGIN ... PRIVATE KEY-----`, PGP included, to the end of the text
  when the block was cut), a Laravel `APP_KEY` (`base64:`) and a Quiet Guard
  project key (`lm_`). The new shapes form `ValueRedactor::CREDENTIALS`, run
  before the personal ones (a GitHub token starting with digits came out as
  `[redacted:phone]`) and keep the precision rule: a class name, a git hash,
  a UUID or a word carrying a prefix without the token behind it travels.
- The password of a `user:password@host` written into an address of any
  scheme is masked wherever the address sits in a text (`url_password`,
  `[redacted:password]`), the scheme, the user and the host staying readable.
  The `Scrubber` only read an address that opens a string, and an exception
  message never went through it; the email shape then ate the password and
  the host together. The slashes may arrive escaped (`redis:\/\/`, as
  json_encode writes them, for an application key too), the user may carry an
  `@` (a mailer DSN), the password an `@` or a `/`: it runs to the last `@`
  of the authority.
- A hard cut before masking halved a token straddling the limit, and its
  first half, the prefix, left in clear. `Cut::soft()` cuts on the first
  whitespace past the limit, `Cut::before()` applies it to the message and
  the snippet lines before masking (the `Reporter` calls it), and the hard
  cut of `Cut::payload()` lands on masked text. `Cut::before()` also replaces
  a context whose JSON exceeds the 65 535 bytes the server keeps by the
  server's own marker, `environment`, `release` and `occurred_at` kept, rather
  than scanning megabytes the server drops.
- The exact list every client shipped before this version,
  `['email', 'iban', 'nir', 'card', 'phone']` in that order
  (`ValueRedactor::LEGACY_DEFAULT`), is read as the default it was: every
  published configuration carries it, and read literally it would have
  switched every credential shape off for whoever followed the installation
  page.
- A masking failure withholds the field instead of sending it as it came: a
  PCRE failure on a built-in pattern, or on a custom one that compiled, replaces
  the field whole by `ValueRedactor::UNSCANNABLE` (`[redacted:unscannable]`).
  A string over 64 KB, formerly skipped whole, is read in pieces cut on a line
  break (failing that a space, failing that a byte outside the token
  alphabet), the key block being read on the whole text first. A custom
  pattern that does not compile is dropped at construction, as before: a
  configuration error, not an unreadable value. A piece never ends between
  the bytes of one character, or a custom pattern written with `/u` failed on
  it. The private key block is read without backtracking, so a block of a
  megabyte comes out masked rather than unscannable.
- A percent-encoded value is read decoded (`ValueRedactor`): `fullUrl()` and
  `getUri()` write the query string encoded, so an email (`%40`), a number,
  an IBAN or a card written with spaces (`%20`), a DSN or an application key
  passed as a parameter left in clear in the reported URL. Only the part that
  changed is rewritten, the mask unencoded (`?email=[redacted:email]`), the
  rest byte for byte.
- `Scrubber::scrubLines()` masks whole a line that hands a string literal to a
  call whose arguments are credentials (`Scrubber::CREDENTIAL_CALLS`: `new
  PDO`, `new mysqli`, `mysqli_connect`, `mysqli_real_connect`,
  `mysql_connect`, `pg_connect`, `pg_pconnect`, `oci_connect`, `ldap_bind`,
  `ftp_login`, `imap_open`, `ssh2_auth_password`, PHP 8.4's `PDO::connect` and
  `Pdo\Mysql::connect` / `Pdo\Pgsql::connect` / `Pdo\Sqlite::connect`
  factories, and `->real_connect`). A call passing variables,
  or a literal nested in another call (`env('DB_PASSWORD')`), stays readable.

### Added

- `Scrubber::masks(string $key): bool` and `Scrubber::masksParameter(string
  $name): bool`, the key rule and the address-parameter rule made public, for
  an adapter to ask about a name of its own (the Laravel SDK asks about route
  parameters, `{hash}` of the email verification link included).
- `ValueRedactor::CREDENTIALS`, `ValueRedactor::PERSONAL`,
  `ValueRedactor::LEGACY_DEFAULT`, `ValueRedactor::UNSCANNABLE` and
  `ValueRedactor::CHUNK_BYTES`; `Cut::soft()`, `Cut::before()`, `Cut::SLACK`,
  `Cut::CONTEXT_MARKER` and `Cut::LIMITS['context']`.
- `ValueRedactor::redactAll()` keeps two keys masked to the same label as two
  rows (`[redacted:email]`, `[redacted:email] (2)`) rather than one replacing
  the other.

## v0.5.0

No change in the core: released alongside the Laravel SDK, whose
`monitor:backup --exclude-table` needs no new core API.

## v0.4.0

No change in the core: released alongside the Laravel SDK, whose automatic
heartbeats need no new core API.

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
  password beside that number travelled with it. The names are read in one
  pass, literal after literal, never by a pattern retried from every quote,
  then once more without pairing quotes, so that a stray quote earlier in the
  text does not hide a `"password":` after it.
- A string that starts with an absolute `http(s)` URL is masked as an address
  (`Scrubber::scrubUrl()`, public): the values of the query-string parameters
  and of the fragment's `name=value` pairs whose name matches, and every path
  segment made of forty letters or digits in a row, whatever the list says. A
  password reset link carries its token in the query or in the path
  (`/reset-password/{token}` in Breeze, Fortify and Jetstream), and a context
  value holding one, Symfony's `request.url` for instance, carried it in
  clear. A number, a slug, a UUID or a ULID stays; the scheme, the host, the
  port and the user of a userinfo travel as they came, its password is
  masked (`user:%5Bscrubbed%5D@`), since a URL typed into a form field or a
  webhook setting carries it; a relative address is not reached. A string
  that starts with an address of any other scheme, a DSN such as
  `mysql://root:secret@db/app` or `redis://:secret@cache:6379`, has the
  password of its userinfo masked the same way, and the values of its
  query-string parameters whose name matches, since a DSN writes its options
  there (`tcp://127.0.0.1:6379?password=...`); the path-token rule stays the
  web's.
  The text after the URL is handed back as it came, except a pair opened by
  `&`, `?` or `#` whose name matches.
- Four parameter names of an address are masked whatever the list holds,
  since a link carrying one is a working credential until it expires: `hash`
  (Symfony's login links, beside `user` and `expires`), `_hash` (Symfony's
  `UriSigner`, beside `_expiration`), `sig` (Azure's shared access
  signatures) and `signature` (`Scrubber::URL_CREDENTIALS`). The name is
  matched exactly, decoded and regardless of case, so `hashtag` and
  `content_hash` stay, and only in the query, the fragment and the pairs after
  the URL: in the key lists `hash` would mask every key containing it and
  every snippet line calling `hash('sha256', ...)`.
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
