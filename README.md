# Quiet Guard: PHP core

Framework-agnostic PHP client core for Quiet Guard,
the Laravel-first monitoring platform (exceptions, logs, dependency security, uptime).

This package contains the platform-neutral building blocks shared by every
Quiet Guard client: the Laravel SDK (`quiet-guard/laravel-monitor`), the
Symfony bundle and the WordPress plugin are all thin adapters over it. If you
use one of those, you do not need to install this package directly. Use it only
to build a client for another platform or for a plain-PHP application.

## Requirements

- PHP 8.2+
- `ext-curl` (default transport) and `ext-sodium` (encrypted backups)

## Installation

```bash
composer require quiet-guard/monitor-php
```

## What it provides

| Class | Role |
|---|---|
| `QuietGuard\Monitor\Config` | Immutable client configuration (server URL, project key, timeout, release, environments, trace limit). |
| `QuietGuard\Monitor\Reporter` | The platform-neutral client: `reportException()`, `sendLogs()`, `sendDependencies()`. Never throws. |
| `QuietGuard\Monitor\ErrorHandler` | Global PHP exception, error and fatal-shutdown handlers for hosts without a framework pipeline. |
| `QuietGuard\Monitor\Payload\ExceptionPayloadBuilder` | Builds the ingestion payload from a `Throwable` (full stack trace by default, frame arguments never sent). |
| `QuietGuard\Monitor\Support\Scrubber` | Masks sensitive values by key, recursively, before anything leaves the app. |
| `QuietGuard\Monitor\Http\HttpClient` / `CurlHttpClient` | Transport interface and its dependency-free curl implementation. |
| `QuietGuard\Monitor\Backup\BackupCipher` | Hybrid secretstream encryption for the zero-knowledge backup vault. |

## Quickstart

Wire a reporter and register the global handlers (plain-PHP host):

```php
use QuietGuard\Monitor\Config;
use QuietGuard\Monitor\ErrorHandler;
use QuietGuard\Monitor\Http\CurlHttpClient;
use QuietGuard\Monitor\Reporter;
use QuietGuard\Monitor\Support\Scrubber;

$config = new Config(
    url: 'https://monitor.example.com',
    key: 'lm_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
    timeout: 3,
    release: null,          // e.g. a git SHA
    environments: [],       // report from every environment
    traceLimit: 0,          // 0 = full stack trace (the default)
);

$reporter = new Reporter(
    $config,
    new CurlHttpClient,
    new Scrubber(['password', 'passphrase', 'token', 'secret', 'authorization', 'cookie', 'referer', 'referrer']),
);

// Global exception / error / fatal-shutdown handlers.
// Frameworks with their own exception pipeline should NOT call this.
ErrorHandler::register($reporter);

// Or report manually:
$reporter->reportException($e, ['order_id' => 42]);
```

The payload builder is derived from the `Config` (its `release` and
`traceLimit` apply to every report); pass your own
`Payload\ExceptionPayloadBuilder` as the fourth argument only to override it.

`key` is the per-project API key generated in the Quiet Guard dashboard
(shown only once at creation). Reporting is fail-safe by design: transport or
configuration errors are swallowed (optionally logged through a PSR-3 logger
passed to `Reporter`) and never break the host application.

`ErrorHandler::register()` is additive: a previously registered exception
handler still runs after the report, and when none exists the uncaught
exception is written to `error_log` exactly as PHP would have done.

## Privacy

The `Scrubber` masks configured keys (passwords, tokens, cookies...) recursively
in every payload, and stack-trace frame arguments are never sent: only file,
line, function, class and call type.

## Documentation

Full documentation is served by your Quiet Guard server under `/docs`
(for example `https://monitor.example.com/docs`), including a dedicated
section for this package.

## License

MIT. See [LICENSE](LICENSE).
