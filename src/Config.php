<?php

namespace QuietGuard\Monitor;

use QuietGuard\Monitor\Support\ValueRedactor;

/**
 * Immutable client configuration shared by every platform adapter.
 */
class Config
{
    /**
     * The address of the service, applied when nothing is configured.
     *
     * It lives HERE, in the code that reads the value, and not only in the
     * publishable configuration template. A template is a COPY: the
     * installation page tells every reader to publish it, their copy is frozen
     * at the installed version, and it wins over the package's defaults. A
     * default written there alone therefore reaches nobody, exactly the case
     * measured on quietmetrics.dev on 2026-09-08, where the configuration
     * published under 0.2.0 made `url` null despite the default added in
     * 0.2.1.
     */
    public const HOSTED_URL = 'https://quietguard.dev';

    /**
     * The base address, already normalised: no whitespace, no trailing slash
     * and no API prefix, since every call carries its own.
     */
    public readonly string $url;

    /**
     * @param  array<int, string>  $environments  report only from these (empty = all)
     * @param  array<int, string>  $redact  value patterns to mask before sending
     * @param  array<string, string>  $customRedactions  label => PCRE pattern
     */
    public function __construct(
        ?string $url,
        public readonly ?string $key,
        public readonly int $timeout = 3,
        public readonly ?string $release = null,
        public readonly array $environments = [],
        public readonly int $traceLimit = 0,
        // On by default. Masking personal data at the source is what article
        // 25.2 calls protection by default, and a setting nobody turns on
        // protects nobody. Pass an empty array to send payloads untouched.
        public readonly array $redact = ValueRedactor::PATTERNS,
        public readonly array $customRedactions = [],
        // A few lines of the application's own source around each frame, so
        // the dashboard can show the failing line in context. Dependencies
        // never send theirs. Off, only file and line travel.
        public readonly bool $codeSnippets = true,
    ) {
        $this->url = self::normaliseUrl($url);
    }

    /**
     * A usable base address, whatever we were given.
     *
     * Strips the API prefix the caller may have supplied: every path already
     * carries its `/api/v1`, and "the base URL of your server" reads just as
     * well as "the address of the API". Both readings have to work, because
     * the wrong one answers 404 everywhere and looks exactly like an invalid
     * key. A rule that has to be obeyed is weaker than a shape that cannot be
     * got wrong.
     */
    public static function normaliseUrl(?string $url): string
    {
        $url = rtrim(trim((string) $url), '/');

        if ($url === '') {
            return self::HOSTED_URL;
        }

        return (string) preg_replace('#/api(/v\d+)?$#i', '', $url);
    }

    public function redactor(): ValueRedactor
    {
        return new ValueRedactor($this->redact, $this->customRedactions);
    }

    /**
     * The key is the one thing we cannot guess.
     *
     * The address is one we can: it defaults to the hosted service. Requiring
     * both made an installation fail that lacked nothing irreplaceable, under
     * a message that blamed the key.
     */
    public function isConfigured(): bool
    {
        return ! empty($this->key);
    }

    public function reportsFrom(?string $environment): bool
    {
        return $this->environments === [] || in_array($environment, $this->environments, true);
    }
}
