<?php

namespace LaBoiteACode\Monitor;

use LaBoiteACode\Monitor\Support\ValueRedactor;

/**
 * Immutable client configuration shared by every platform adapter.
 */
class Config
{
    /**
     * @param  array<int, string>  $environments  report only from these (empty = all)
     * @param  array<int, string>  $redact  value patterns to mask before sending
     * @param  array<string, string>  $customRedactions  label => PCRE pattern
     */
    public function __construct(
        public readonly ?string $url,
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
    ) {}

    public function redactor(): ValueRedactor
    {
        return new ValueRedactor($this->redact, $this->customRedactions);
    }

    public function isConfigured(): bool
    {
        return ! empty($this->url) && ! empty($this->key);
    }

    public function reportsFrom(?string $environment): bool
    {
        return $this->environments === [] || in_array($environment, $this->environments, true);
    }
}
