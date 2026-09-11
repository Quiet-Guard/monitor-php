# Changelog

All notable changes to `quiet-guard/monitor-php`.

## Unreleased

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
